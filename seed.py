import os
import pymysql

# Fetch the MariaDB credentials from the environment variables
# Usually available in Railway as MARIADB_USER, MARIADB_PASSWORD, MARIADB_PRIVATE_HOST, MARIADB_PRIVATE_PORT, MARIADB_DATABASE
# Or we can construct it if MYSQL_URL is not there.

db_host = os.environ.get("MARIADB_PRIVATE_HOST", "mariadb.railway.internal")
db_user = os.environ.get("MARIADB_USER", "railway")
db_password = os.environ.get("MARIADB_PASSWORD", "")
db_name = os.environ.get("MARIADB_DATABASE", "railway")
db_port = int(os.environ.get("MARIADB_PRIVATE_PORT", 3306))

try:
    connection = pymysql.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_name,
        port=db_port,
        cursorclass=pymysql.cursors.DictCursor
    )
    print("Connected to MariaDB successfully.")
except Exception as e:
    print(f"Error connecting to MariaDB: {e}")
    exit(1)

try:
    with connection.cursor() as cursor:
        # Create token_rates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS token_rates (
                id INT AUTO_INCREMENT PRIMARY KEY,
                model_name VARCHAR(255) UNIQUE NOT NULL,
                credits_per_1k INT NOT NULL,
                api_cost DECIMAL(10, 4) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Create credit_packages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credit_packages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                price_eur DECIMAL(10, 2) NOT NULL,
                credits INT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Create subscriptions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                price_eur DECIMAL(10, 2) NOT NULL,
                credits_per_month INT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Create services table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                status VARCHAR(50) NOT NULL,
                url VARCHAR(255)
            )
        """)

        print("Tables created successfully (if they didn't exist).")

        # Insert/Replace Token Rates: Gemini Flash (15), Claude Sonnet (80), Gemini Pro (120), GPT-5 (120), Claude Opus (350).
        token_rates_data = [
            ("Gemini Flash", 15, 0.00),
            ("Claude Sonnet", 80, 0.00),
            ("Gemini Pro", 120, 0.00),
            ("GPT-5", 120, 0.00),
            ("Claude Opus", 350, 0.00)
        ]
        for name, credits_val, api_cost in token_rates_data:
            cursor.execute("""
                INSERT INTO token_rates (model_name, credits_per_1k, api_cost, is_active)
                VALUES (%s, %s, %s, TRUE)
                ON DUPLICATE KEY UPDATE 
                credits_per_1k = VALUES(credits_per_1k),
                api_cost = VALUES(api_cost),
                is_active = VALUES(is_active)
            """, (name, credits_val, api_cost))

        # Insert/Replace Credit Packages: Starter (gratis trial/0 euro), Pro (29.99 / 35.000 credits), Enterprise (99.99 / 125.000 credits).
        credit_packages_data = [
            ("Starter", 0.00, 5000), # Not specified credits for starter, let's say 5000 or similar
            ("Pro", 29.99, 35000),
            ("Enterprise", 99.99, 125000)
        ]
        for name, price, credits_val in credit_packages_data:
            cursor.execute("""
                INSERT INTO credit_packages (name, price_eur, credits, is_active)
                VALUES (%s, %s, %s, TRUE)
                ON DUPLICATE KEY UPDATE 
                price_eur = VALUES(price_eur),
                credits = VALUES(credits),
                is_active = VALUES(is_active)
            """, (name, price, credits_val))

        # Insert/Replace Subscriptions (same names, assuming they act as both or separate tables)
        subscriptions_data = [
            ("Starter", 0.00, 5000),
            ("Pro", 29.99, 35000),
            ("Enterprise", 99.99, 125000)
        ]
        for name, price, credits_val in subscriptions_data:
            cursor.execute("""
                INSERT INTO subscriptions (name, price_eur, credits_per_month, is_active)
                VALUES (%s, %s, %s, TRUE)
                ON DUPLICATE KEY UPDATE 
                price_eur = VALUES(price_eur),
                credits_per_month = VALUES(credits_per_month),
                is_active = VALUES(is_active)
            """, (name, price, credits_val))

        # Services: "Blog Idea Generator" (https://roboserve-vite-production.up.railway.app/services/blog-ideas) 
        # "AI Logo Creator" live. 3 placeholders coming-soon.
        services_data = [
            ("Blog Idea Generator", "live", "https://roboserve-vite-production.up.railway.app/services/blog-ideas"),
            ("AI Logo Creator", "live", "https://roboserve-logo-api-production.up.railway.app"), # Placeholder URL or empty
            ("Content Repurposing", "coming-soon", ""),
            ("SEO Optimizer", "coming-soon", ""),
            ("Cold Email Drafter", "coming-soon", "")
        ]
        for name, status, url in services_data:
            cursor.execute("""
                INSERT INTO services (name, status, url)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                status = VALUES(status),
                url = VALUES(url)
            """, (name, status, url))

        connection.commit()
        print("Seed data inserted/updated successfully.")

finally:
    connection.close()
