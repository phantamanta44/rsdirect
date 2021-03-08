use std::{collections::HashMap, fs::File, path::Path, str::FromStr};

use clap::{App, Arg};
use http::uri::{InvalidUri, Uri};
use warp::{Filter, filters::BoxedFilter, redirect, Reply};

fn gen_filter(domain: &String, redir_url: &String, port: u16) -> Result<BoxedFilter<(Box<dyn Reply>, )>, InvalidUri> {
    let redir_uri = Uri::from_str(&redir_url)?;
    Ok(Filter::boxed(warp::host::exact(domain).or(warp::host::exact(format!("{}:{}", domain, port).as_str()))
        .map(move |_| Box::new(redirect(redir_uri.clone())) as Box<dyn Reply>)))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    // parse args
    let args = App::new("rsdirect")
        .about("Simple Rust redirecting web server")
        .arg(Arg::with_name("CONF-FILE")
            .index(1).required(true)
            .help("A file specifying a set of redirects"))
        .arg(Arg::with_name("port")
            .short("p").long("port").takes_value(true).default_value("8080"))
        .arg(Arg::with_name("tls-key")
            .short("K").long("tls-key").takes_value(true).requires("tls-cert"))
        .arg(Arg::with_name("tls-cert")
            .short("C").long("tls-cert").takes_value(true).requires("tls-key"))
        .get_matches();
    let port = u16::from_str(args.value_of("port").unwrap()).map_err(|e| e.to_string())?;

    // init logging
    env_logger::init();
    log::info!("Booting up rsdirect...");

    // parse config file
    let conf_file_name = args.value_of("CONF-FILE")
        .ok_or("No config file specified!")?;
    let conf_file = File::open(Path::new(conf_file_name)).map_err(|e| e.to_string())?;
    let redirs: HashMap<String, String> = serde_json::from_reader(conf_file).map_err(|e| e.to_string())?;

    // generate filters
    let mut rt_filter_iter = redirs.iter()
        .map(|(d, r)| gen_filter(d, r, port).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?.into_iter();
    let rt_filter_fst = rt_filter_iter.next().ok_or("No redirects specified!")?;
    let rt_filter: BoxedFilter<(Box<dyn Reply>, )> = rt_filter_iter.fold(
        rt_filter_fst, |fa, fb| Filter::boxed(fa.or(fb).map(|e| Box::new(e) as Box<dyn Reply>)));
    let filter = warp::get().and(rt_filter.with(warp::log::custom(|info| {
        log::info!("{} -> {}{} ({} {})",
                   info.remote_addr().map(|a| a.to_string()).as_deref().unwrap_or("<no remote addr>"),
                   info.host().unwrap_or("<no host>"),
                   info.path(),
                   info.referer().unwrap_or("<no referer>"),
                   info.user_agent().unwrap_or("<no user agent>"));
    })));

    // start server
    let server_addr: ([u8; 4], u16) = ([0, 0, 0, 0], port);
    if args.is_present("tls-key") {
        let server = warp::serve(filter).tls()
            .key_path(Path::new(args.value_of("tls-key").unwrap()))
            .cert_path(Path::new(args.value_of("tls-cert").unwrap()));
        log::info!("Starting server with TLS on port {}!", server_addr.1);
        server.run(server_addr).await;
    } else {
        let server = warp::serve(filter);
        log::info!("Starting server on port {}!", server_addr.1);
        server.run(server_addr).await;
    }

    // job's done
    Ok(())
}
