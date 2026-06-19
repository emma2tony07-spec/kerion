import os
import sys
import traceback
from flask import Flask, jsonify, request
from flask_cors import CORS

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    CORS(app, resources={r"/api/*": {"origins": "*"}, r"/debug/*": {"origins": "*"}})
    
    @app.route('/')
    def home():
        return jsonify({
            "status": "ok",
            "app": "Kerion Wallet API",
            "version": "1.0.2"
        })
    
    @app.route('/health')
    def health():
        return jsonify({"status": "healthy"}), 200
    
    # ═══════════ DEBUG: Check individual env vars ═══════════
    @app.route('/debug/env', methods=['GET'])
    def debug_env():
        vars_to_check = [
            'FIREBASE_TYPE',
            'FIREBASE_PROJECT_ID',
            'FIREBASE_PRIVATE_KEY_ID',
            'FIREBASE_PRIVATE_KEY',
            'FIREBASE_CLIENT_EMAIL',
            'FIREBASE_CLIENT_ID',
            'FIREBASE_TOKEN_URI',
            'FIREBASE_DATABASE_URL',
            'FIREBASE_API_KEY',
        ]
        result = {}
        for var in vars_to_check:
            val = os.environ.get(var)
            if not val:
                result[var] = "NOT SET"
            elif var == 'FIREBASE_PRIVATE_KEY':
                # Show start and end to verify format without exposing full key
                result[var] = f"SET (starts: {val[:25]}... ends: ...{val[-25:]})"
            else:
                result[var] = f"SET ({val[:40]}{'...' if len(val) > 40 else ''})"
        return jsonify({"success": True, "environment": result})
    
    @app.route('/debug/firebase', methods=['GET'])
    def debug_firebase():
        steps = []
        
        # Step 1: Check individual env vars
        required = ["FIREBASE_PROJECT_ID", "FIREBASE_PRIVATE_KEY", "FIREBASE_CLIENT_EMAIL", "FIREBASE_DATABASE_URL"]
        missing = [r for r in required if not os.environ.get(r)]
        
        steps.append({
            "step": "check_env_vars",
            "missing": missing,
            "all_present": len(missing) == 0
        })
        
        if missing:
            return jsonify({
                "success": False,
                "error": f"Missing env vars: {', '.join(missing)}",
                "steps": steps
            }), 500
        
        # Step 2: Check private key format
        private_key = os.environ.get("FIREBASE_PRIVATE_KEY", "")
        has_begin = "-----BEGIN PRIVATE KEY-----" in private_key
        has_end = "-----END PRIVATE KEY-----" in private_key
        has_newlines = "\n" in private_key
        
        steps.append({
            "step": "check_private_key",
            "has_begin": has_begin,
            "has_end": has_end,
            "has_newlines": has_newlines,
            "length": len(private_key)
        })
        
        if not has_begin or not has_end:
            return jsonify({
                "success": False,
                "error": "Private key is missing BEGIN/END markers. Paste the full key including the ----- lines.",
                "steps": steps
            }), 500
        
        # Step 3: Try init
        try:
            import firebase_admin
            from firebase_admin import credentials, db
            
            # Fix newlines if needed
            fixed_key = private_key
            if "\\n" in fixed_key:
                fixed_key = fixed_key.replace("\\n", "\n")
                steps.append({"step": "fixed_newlines", "was_escaped": True})
            
            cred_dict = {
                "type": os.environ.get("FIREBASE_TYPE", "service_account"),
                "project_id": os.environ.get("FIREBASE_PROJECT_ID"),
                "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID", ""),
                "private_key": fixed_key,
                "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
                "client_id": os.environ.get("FIREBASE_CLIENT_ID", ""),
                "token_uri": os.environ.get("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": f"https://www.googleapis.com/robot/v1/metadata/x509/{os.environ.get('FIREBASE_CLIENT_EMAIL', '').replace('@', '%40')}",
            }
            
            try:
                app_obj = firebase_admin.get_app()
                steps.append({"step": "firebase_init", "already_initialized": True})
            except ValueError:
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred, {
                    "databaseURL": os.environ.get("FIREBASE_DATABASE_URL")
                })
                steps.append({"step": "firebase_init", "initialized_now": True})
            
            # Step 4: Test DB read
            ref = db.reference('/')
            kr_tags = ref.child('kr_tags').get()
            steps.append({
                "step": "db_read",
                "success": True,
                "kr_tags": kr_tags
            })
            
            return jsonify({
                "success": True,
                "message": "Firebase is fully working",
                "steps": steps
            })
            
        except Exception as e:
            steps.append({
                "step": "error",
                "error": str(e),
                "traceback": traceback.format_exc()[-500:]
            })
            return jsonify({
                "success": False,
                "error": str(e),
                "steps": steps
            }), 500
    
    # ═══════════ REGISTER BLUEPRINTS ═══════════
    try:
        from auth.routes import auth_bp
        from wallet.routes import wallet_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(wallet_bp)
        print("Blueprints registered successfully.")
    except Exception as e:
        print(f"WARNING: Could not register blueprints: {e}")
        
        @app.route('/api/auth/signup', methods=['POST'])
        def fallback_signup():
            return jsonify({
                "success": False,
                "error": f"Server init error. Hit /debug/firebase first. ({str(e)[:200]})"
            }), 500
        
        @app.route('/api/auth/login', methods=['POST'])
        def fallback_login():
            return jsonify({
                "success": False,
                "error": f"Server init error. Hit /debug/firebase first. ({str(e)[:200]})"
            }), 500
    
    # ═══════════ ERROR HANDLERS ═══════════
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "Endpoint not found."
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "success": False,
            "error": "Internal server error."
        }), 500
    
    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
