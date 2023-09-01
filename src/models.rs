use sqlx::{SqlitePool, FromRow};
use sqlx::Error;
use serde::{Deserialize, Serialize};

use sha2::Digest;
use sha2::Sha256;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub username: String,
    pub password: String,
    pub email: String,
    pub country_code: i32,
    pub phone: i64,
}

#[derive(FromRow)]
pub struct  UserSelect {
    pub id: i32,
}

pub async fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::default();
    hasher.update(password);
    let hashed_password = hasher.finalize();
    format!("{:x}", hashed_password)
}

pub async fn create_user_table(pool: &SqlitePool) -> Result<(), Box<dyn std::error::Error>> {
    match sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS User (
            id INTEGER PRIMARY KEY,
            username VARCHAR(16) NOT NULL,
            password VARCHAR(65) NOT NULL,
            email VARCHAR(128) NOT NULL,
            country_code INTEGER NOT NULL,
            phone INTEGER NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT 0
        )
        "#,
    )
    .execute(pool)
    .await
    {
        Ok(_) => {
            println!("User tablosu başarıyla oluşturuldu.");
            Ok(())
        }
        Err(err) => {
            eprintln!("Hata: {:?}", err);
            Err(Box::new(err))
        }
    }
}

pub async fn create_user(pool: &SqlitePool, user: &User) -> Result<(), Error> {
    let hashed_password = hash_password(&user.password).await;

    sqlx::query(
        r#"
        INSERT INTO User (id, username, password, email, country_code, phone)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind("1")
    .bind(&user.username)
    .bind(hashed_password) // Şifreyi hash'lenmiş haliyle bind ediyoruz
    .bind(&user.email)
    .bind(user.country_code)
    .bind(user.phone)
    .execute(pool)
    .await
    .map(|_| ())
}

pub async fn find_user(pool: &SqlitePool, username: &str, password: &str) -> Result<Option<UserSelect>, Error> {
    let hashed_password = hash_password(password).await;

    match sqlx::query_as::<_, UserSelect>(
        r#"
        SELECT * FROM User WHERE username = ? AND password = ?
        "#,
    )
    .bind(username)
    .bind(hashed_password)
    .fetch_one(pool)
    .await
    {
        Ok(user) => Ok(Some(user)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub async fn find_user_by_id(pool: &SqlitePool, user_id: i32) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM User WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}
