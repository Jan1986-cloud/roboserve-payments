import re

with open("main.py", "r") as f:
    content = f.read()

# We need to replace everything from @app.get("/api/admin/packages" to the end with new endpoints
start_marker = '@app.get("/api/admin/packages", dependencies=[Depends(verify_admin_password)])'

parts = content.split(start_marker)

new_content = parts[0] + start_marker + '''
async def get_admin_packages():
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM credit_packages")
                return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/packages", dependencies=[Depends(verify_admin_password)])
async def create_admin_package(request: Request):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO credit_packages (name, price_eur, credits, is_active) VALUES (%s, %s, %s, %s)",
                            (data.get('name'), data.get('price_eur'), data.get('credits'), data.get('is_active', True)))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/packages/{id}", dependencies=[Depends(verify_admin_password)])
async def update_admin_package(id: int, request: Request):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE credit_packages SET name=%s, credits=%s, price_eur=%s, is_active=%s WHERE id=%s",
                            (data.get('name'), data.get('credits'), data.get('price_eur'), data.get('is_active', True), id))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/packages/{id}", dependencies=[Depends(verify_admin_password)])
async def delete_admin_package(id: int):
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM credit_packages WHERE id=%s", (id,))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/subscriptions", dependencies=[Depends(verify_admin_password)])
async def get_admin_subscriptions():
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM subscriptions")
                return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/subscriptions", dependencies=[Depends(verify_admin_password)])
async def create_admin_subscription(request: Request):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO subscriptions (name, price_eur, credits_per_month, is_active) VALUES (%s, %s, %s, %s)",
                            (data.get('name'), data.get('price_eur'), data.get('credits_per_month'), data.get('is_active', True)))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/subscriptions/{id}", dependencies=[Depends(verify_admin_password)])
async def update_admin_subscription(id: int, request: Request):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE subscriptions SET name=%s, credits_per_month=%s, price_eur=%s, is_active=%s WHERE id=%s",
                            (data.get('name'), data.get('credits_per_month'), data.get('price_eur'), data.get('is_active', True), id))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/subscriptions/{id}", dependencies=[Depends(verify_admin_password)])
async def delete_admin_subscription(id: int):
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM subscriptions WHERE id=%s", (id,))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/rates", dependencies=[Depends(verify_admin_password)])
async def get_admin_rates():
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM token_rates")
                return cur.fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/rates", dependencies=[Depends(verify_admin_password)])
async def create_admin_rate(request: Request):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO token_rates (model_name, credits_per_1k, api_cost, is_active) VALUES (%s, %s, %s, %s)",
                            (data.get('model_name'), data.get('credits_per_1k'), data.get('api_cost'), data.get('is_active', True)))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/rates/{id}", dependencies=[Depends(verify_admin_password)])
async def update_admin_rate(id: int, request: Request):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE token_rates SET model_name=%s, credits_per_1k=%s, api_cost=%s, is_active=%s WHERE id=%s",
                            (data.get('model_name'), data.get('credits_per_1k'), data.get('api_cost'), data.get('is_active', True), id))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/admin/rates/{id}", dependencies=[Depends(verify_admin_password)])
async def delete_admin_rate(id: int):
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM token_rates WHERE id=%s", (id,))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/users", dependencies=[Depends(verify_admin_password)])
async def get_admin_users():
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, email, name, credits, is_subscriber, subscription_plan, is_admin, created_at FROM users ORDER BY created_at DESC")
                users = cur.fetchall()
                for u in users:
                    if u['created_at']:
                        u['created_at'] = str(u['created_at'])
                return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/users/{email}/plan", dependencies=[Depends(verify_admin_password)])
async def update_admin_user_plan(email: str, request: Request):
    data = await request.json()
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET subscription_plan=%s, is_subscriber=%s WHERE email=%s",
                            (data.get('subscription_plan'), data.get('is_subscriber', False), email))
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/admin/users/{email}/credits", dependencies=[Depends(verify_admin_password)])
async def update_admin_user_credits(email: str, request: Request):
    data = await request.json()
    amount_change = data.get('amount', 0)
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, credits FROM users WHERE email=%s", (email,))
                user = cur.fetchone()
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")
                
                new_credits = user['credits'] + amount_change
                if new_credits < 0: new_credits = 0
                
                cur.execute("UPDATE users SET credits=%s WHERE email=%s", (new_credits, email))
                cur.execute("INSERT INTO credit_transactions (user_id, amount, balance_after, tx_type, description) VALUES (%s, %s, %s, %s, %s)",
                            (user['id'], amount_change, new_credits, 'admin_adjustment', 'Admin panel adjustment'))
        return {"status": "success", "new_credits": new_credits}
    except Exception as e:
        if isinstance(e, HTTPException): raise e
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/usage-logs", dependencies=[Depends(verify_admin_password)])
async def get_admin_usage_logs():
    import os, json
    log_file = os.path.expanduser("~/clawd/logs/blog-api-usage.jsonl")
    logs = []
    try:
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                # Get last 100 lines and reverse
                recent_lines = reversed(lines[-100:])
                for line in recent_lines:
                    if not line.strip(): continue
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/services", dependencies=[Depends(verify_admin_password)])
async def get_admin_services_v2():
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM services")
                services = cur.fetchall()
                return {"services": services}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/services/{service_id}", dependencies=[Depends(verify_admin_password)])
async def update_admin_service_status_v2(service_id: str, request: Request):
    data = await request.json()
    new_status = data.get("status", "off")
    # Als service_id een integer is (id), probeer int. Als het een string is (naam), gebruik als string.
    try:
        with db() as db_conn:
            with db_conn.cursor() as cur:
                if service_id.isdigit():
                    cur.execute("UPDATE services SET status=%s, name=%s, url=%s WHERE id=%s", (new_status, data.get('name'), data.get('url'), int(service_id)))
                else:
                    cur.execute("UPDATE services SET status=%s WHERE name=%s", (new_status, service_id))
            db_conn.commit()
        return {"status": "updated", "service_id": service_id, "new_status": new_status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
'''

with open("main.py", "w") as f:
    f.write(new_content)

