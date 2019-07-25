#[macro_use]
extern crate log;
extern crate oauth2;
extern crate micro_http_server;
extern crate url;
extern crate open;
extern crate bincode;
extern crate serde;

pub mod local_client {
    use std::thread;
    use std::time::Duration;
    use std::collections::HashMap;
    use micro_http_server::MicroHTTP;
    use std::sync::mpsc::{Sender, Receiver};
    use std::sync::mpsc;
    use std::path::PathBuf;
    use oauth2::{Config, Token, TokenError};
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize)]
    pub struct TokenStore {
        token: Option<Token>
    }

    pub struct OAuth2Client {
        auto_open_browser: bool,
        oauth_config: Config,
        cache_path: PathBuf,
        ok_message: String,
        token_store: TokenStore,
        empty_cache: bool
    }
    impl OAuth2Client {
        // create a new struct
        pub fn new(client_id: &str, client_secret: &str, auth_url: &str, token_url: &str) -> Self {
            let mut oauth_config = Config::new(
                    client_id,
                    client_secret,
                    auth_url,
                    token_url
                );
            oauth_config = oauth_config.set_redirect_url("http://localhost:8080");

            Self {
                auto_open_browser: false,
                oauth_config,
                ok_message: String::from("I received access code from remote auth service. You can now close this window :)"),
                cache_path: PathBuf::default(),
                token_store: TokenStore {
                    token: None
                },
                empty_cache: false
            }
        }

        // set the directory where to store cache for this token
        pub fn set_cache_path(mut self, path: PathBuf) -> Result<Self, std::io::Error> {
            if path.exists() {
                if !path.is_file() {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Defined cache location exists but is not a file."));
                }
            } else {
                // create directories leading to cache file
                std::fs::create_dir_all(path.parent().unwrap().display().to_string())?;
                // write empty presentation of the token cache into it
                let mut f = std::fs::File::create(&path).unwrap();
                bincode::serialize_into(&mut f, &self.token_store).unwrap();
                self.empty_cache = true;
            }
            self.cache_path = path;
            Ok(self)
        }

        // add scope to configuration
        pub fn add_scope(mut self, scope: &str) -> Self {
            self.oauth_config = self.oauth_config.add_scope(scope);
            self
        }

        // by default we dont open a browser but if the flag is set once the step comes along
        //  we can use 'xdg' or some other utility to initiate browser to open automagically
        pub fn open_browser(mut self) -> Self {
            self.auto_open_browser = true;
            self
        }

        // set the message shown by local web server on successful auth code receive from remote
        pub fn set_ok_message(mut self, ok_message: String) -> Self {
            self.ok_message = ok_message;
            self
        }

        // get the authentication code, retrieve it from local http server
        //  and exchange it for bearer token. cache it if requested.
        pub fn get_access_token(mut self) -> Result<Token, TokenError> {
            if self.cache_path.is_file() && !self.empty_cache {
                // read token data from data file
                let f = std::fs::File::open(self.cache_path).unwrap();
                self.token_store = bincode::deserialize_from(f).unwrap();
                // since we read the token from cache refresh it
                let token_result = self.oauth_config.exchange_refresh_token(
                    self.token_store.token.unwrap().refresh_token.unwrap());
                if token_result.is_err() {
                    return token_result;
                } else {
                    self.token_store.token = Some(token_result.unwrap());
                }
            } else {
                let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
                let (tx1, rx1): (Sender<bool>, Receiver<bool>) = mpsc::channel();

                let ok_message = self.ok_message.clone();

                thread::spawn(move || {
                    let server = MicroHTTP::new("127.0.0.1:8080").expect("Could not create server.");
                    debug!("Listening OAuth redirect at http://127.0.0.1:8080/");
                    loop {
                        let result = server.next_client();
                        if result.is_err() {
                            error!("Local response server rerver failed: {:?}", result);
                            break;
                        }

                        match result.unwrap() {
                            None => {},
                            Some(mut client) => {
                                if client.request().is_none() {
                                    trace!("Client {} did not request anything", client.addr());
                                    client.respond_ok("No request :(".as_bytes()).expect("Could not send data to client!");
                                } else {
                                    let request_copy = format!("http://{}{}", "127.0.0.1:8080", client.request().as_ref().unwrap().clone());
                                    trace!("{:?}", request_copy);
                                    client.respond_ok(ok_message.as_bytes()).unwrap();
                                    let parsed_url = url::Url::parse(&request_copy).unwrap();
                                    let hash_query: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();
                                    tx.send(hash_query.get("code").unwrap().clone()).unwrap();
                                }
                            }
                        };

                        if rx1.recv_timeout(Duration::from_secs(1)).unwrap_or(false) {
                            trace!("Received 'done' signal from main thread. Closing local http server.");
                            break;
                        }
                    }
                    debug!("Shutting down local webserver");
                });

                if self.auto_open_browser {
                    if open::that(self.oauth_config.authorize_url().into_string()).is_ok() {
                        debug!("Opened system default browser to: {}", self.oauth_config.authorize_url());
                    }
                } else {
                    println!("Please, open a browser and go to: {}", self.oauth_config.authorize_url());
                }

                let auth_code = rx.recv().unwrap();
                tx1.send(true).unwrap();
                let token_result = self.oauth_config.exchange_code(auth_code);
                if token_result.is_err() {
                    // if token_result is an err we did not succesfully fetch the token therefore return the error
                    return token_result
                } else {
                    self.token_store.token = Some(token_result.unwrap());
                    if self.cache_path.is_file() {
                        // we now have the token, cache it.
                        let mut f = std::fs::File::create(self.cache_path).unwrap();
                        bincode::serialize_into(&mut f, &self.token_store).unwrap();
                    }
                }
            }

            // return the token from our internal token store
            Ok(self.token_store.token.unwrap())
        }
    }
}

// eof
