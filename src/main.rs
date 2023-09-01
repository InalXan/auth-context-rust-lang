use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{SqlitePool};
use std::io;
use std::path::PathBuf;
use tokio::fs;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header, DecodingKey};
use chrono::{Utc, Duration};

mod command;
use command::get_commands;

mod models;
use models::{User, create_user_table, create_user, find_user, find_user_by_id};

#[derive(Debug, Serialize, Deserialize)]
struct JwtPayload {
    user_id: i32,
    exp: usize,
}

fn generate_access_token(user_id: i32) -> String {
    let payload = JwtPayload {
        user_id,
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize, // JWT expires in 1 hour
    };

    let secret_key = b"secret_az";

    let token = encode(&Header::new(Algorithm::HS256), &payload, &EncodingKey::from_secret(secret_key)).unwrap();

    token
}

fn generate_refresh_token() -> String {
    let payload = JwtPayload {
        user_id: 0,
        exp: (Utc::now() + Duration::hours(30)).timestamp() as usize, // JWT expires in 1 hour
    };

    let secret_key = b"secret_refresh_az";

    let token = encode(&Header::new(Algorithm::HS256), &payload, &EncodingKey::from_secret(secret_key)).unwrap();

    token
}

fn extract_user_id_from_token(token: &str, secret_key: &[u8]) -> Option<i32> {
    let decoding_key = DecodingKey::from_secret(secret_key);

    match jsonwebtoken::decode::<JwtPayload>(token, &decoding_key, &jsonwebtoken::Validation::default()) {
        Ok(token_data) => Some(token_data.claims.user_id),
        Err(_) => None,
    }
}

fn validate_port(port_str: Option<String>) -> Option<u16> {
    if let Some(port_str) = port_str {
        if let Ok(port) = port_str.parse::<u16>() {
            if port > 1024 && port <= 9999 {
                return Some(port);
            } else {
                println!("Invalid port number. Please choose a number between 1025 and 9999.");
            }
        } else {
            println!("Invalid port value. Please specify a valid number for port.");
        }
    } else {
        println!("Usage")
    }
    None
}

fn is_valid_username(username: &str) -> bool {
    let username_regex = Regex::new(r"^[a-zA-Z0-9_]{5,16}$").unwrap();
    username_regex.is_match(username)
}

fn is_valid_password(password: &str) -> bool {
    let password_regex = Regex::new(r"^[a-zA-Z0-9]{8,}$").unwrap();
    password_regex.is_match(password)
}

async fn create_pool(db_path: &str) -> Result<SqlitePool, sqlx::Error> {
    sqlx::sqlite::SqlitePoolOptions::new()
        .connect(&db_path)
        .await
}

async fn register(pool: web::Data<SqlitePool>, user: web::Json<User>) -> impl Responder {
    let user_inner = user.into_inner();
    match create_user(pool.as_ref(), &user_inner).await {
        Ok(_) => HttpResponse::Created().json(user_inner),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}


#[derive(Deserialize, Serialize)]
struct LoginData {
    username: String,
    password: String,
}

async fn initialize_database() -> Result<(), Box<dyn std::error::Error>> {
    let db_file_path = std::env::var("DATABASE_URL")?;
    let db_exists = PathBuf::from(&db_file_path).exists();

    if !db_exists {
        println!("No database found!.");
        fs::write(&db_file_path, &[]).await?;
        println!("Create a database: {}", db_file_path);
    } else {
        println!("Database already exists: {}", db_file_path);
    }

    let pool = create_pool(&db_file_path).await?;
    let _ = create_user_table(&pool).await;


    Ok(())
}

async fn login(login_data: web::Json<LoginData>, pool: web::Data<SqlitePool>) -> impl Responder {
    let username = &login_data.username;
    let password = &login_data.password;

    if !is_valid_username(username) {
        return HttpResponse::BadRequest().json(json!({"error": "Invalid username. It must be 5-16 characters and can only contain alphanumeric characters and underscores."}));
    }

    if !is_valid_password(password) {
        return HttpResponse::BadRequest().json(json!({"error": "Invalid password. It must be at least 8 characters and can only contain alphanumeric characters."}));
    }

    match find_user(&pool, username, password).await {
        Ok(Some(user)) => {
            let access_token = generate_access_token(user.id);
            let refresh_token = generate_refresh_token();

            HttpResponse::Ok().json(json!({
                "access_token": access_token,
                "refresh_token": refresh_token
            }))
        }
        _ => {
            // Return JSON data for failed login
            HttpResponse::Unauthorized().json(json!({"error": "Login failed"}))
        }
    }

}

async fn get_profile(info: actix_web::HttpRequest, pool: web::Data<SqlitePool>) -> impl Responder {
    if let Some(auth_header) = info.headers().get("Authorization") {
        if let Ok(header_value) = auth_header.to_str() {
            if let Some(token) = header_value.strip_prefix("Bearer ") {
                if let Some(user_id) = extract_user_id_from_token(token, b"secret_az") {
                    match find_user_by_id(&pool, user_id).await {
                        Ok(user) => {
                            return HttpResponse::Ok().json(user);
                        }
                        Err(_) => {
                            return HttpResponse::NotFound().finish();
                        }
                    }
                }
            }
        }
    }

    HttpResponse::Unauthorized().finish()
}

async fn start_server(port: u16, pool: SqlitePool) -> io::Result<()> {
    println!("Starting Actix Web server at port {}...", port);

    match HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .route("/login", web::post().to(login))
            .route("/register", web::post().to(register))
            .route("/profile", web::get().to(get_profile))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("Error starting server: {}", e);
            Err(e)
        }
    }
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // std::env::set_var("RUST_LOG", "debug");
    // env_logger::init();

    dotenv::dotenv().ok();

    let matches = get_commands().get_matches();

    match matches.subcommand() {
        Some(("runserver", runserver_matches)) => {
            if let Some(port) = validate_port(runserver_matches.get_one::<String>("port").cloned())
            {
                let db_file_path = std::env::var("DATABASE_URL")?;
                let pool = create_pool(&db_file_path).await?;
                let _ = start_server(port, pool.clone()).await?;
            }
        }

        Some(("prepare", runserver_matches)) => {
            if let Some(database_str) = runserver_matches.get_one::<String>("database") {
                if database_str == "all" {
                    let _ = initialize_database().await?;
                } else if database_str == "user" {
                    let db_file_path = std::env::var("DATABASE_URL")?;
                    let pool = create_pool(&db_file_path).await?;
                    let _ = create_user_table(&pool).await;

                } else {
                    println!("Yokkk");
                }
            } else {
                println!("Usage")
            }
        }

        _ => unreachable!(),
    }

    Ok(())
}
