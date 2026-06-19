import os
import json
import traceback
from flask import Flask, jsonify, request
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}, r"/debug/*": {"origins": "*"}})

    # ═══════════════════════════════
    # HEALTH
    # ═══════════════════════════════
    @app.route('/')
    def home():
        return jsonify({
            "status": "ok",
            "app": "Kerion Wallet API",
            "version": "1.0.3"
        })

    @app.route('/health')
    def health():
        return jsonify({"status": "healthy"}), 200

    # ═══════════════════════════════
    # DEBUG
    # ═══════════════════════════════
    @app.route('/debug/status', methods=['GET'])
    def debug_status():
        """Quick overview of what's available."""
        secret_path = "/etc/secrets/firebase-credentials.json"
        local_path = "firebase-credentials.json"

        return jsonify({
            "secret_file_exists": os.path.exists(secret_path),
            "local_file_exists": os.path.exists(local_path),
            "env_vars": {
                "FIREBASE_DATABASE_URL": "SET" if os.environ.get("FIREBASE_DATABASE_URL") else "NOT SET",
                "FIREBASE_API_KEY": "SET" if os.environ.get("FIREBASE_API_KEY") else "NOT SET",
                "FIREBASE_CREDENTIALS": "SET" if os.environ.get("FIREBASE_CREDENTIALS") else "NOT SET",
                "FIREBASE_PRIVATE_KEY": "SET" if os.environ.get("FIREBASE_PRIVATE_KEY") else "NOT SET",
                "FIREBASE_PROJECT_ID": "SET" if os.environ.get("FIREBASE_PROJECT_ID") else "NOT SET",
                "FIREBASE_CLIENT_EMAIL": "SET" if os.environ.get("FIREBASE_CLIENT_EMAIL") else "NOT SET",
            }
        })

    @app.route('/debug/firebase', methods=['GET'])
    def debug_firebase():
        """Full Firebase test."""
        result = {
            "success": False,
            "steps": []
        }

        # Step 1: Find credentials
        secret_path = "/etc/secrets/firebase-credentials.json"
        local_path = "firebase-credentials.json"
        creds_source = None
        cred_dict = None

        if os.path.exists(secret_path):
            creds_source = "secret_file"
            try:
                with open(secret_path) as f:
                    cred_dict = json.load(f)
                result["steps"].append({
                    "step": "load_secret_file",
                    "success": True,
                    "project_id": cred_dict.get("project_id", "?"),
                    "client_email": cred_dict.get("client_email", "?")[:50]
                })
            except Exception as e:
                result["steps"].append({
                    "step": "load_secret_file",
                    "success": False,
                    "error": str(e)
                })
                result["error"] = f"Failed to parse Secret File: {e}"
                return jsonify(result), 500

        elif os.path.exists(local_path):
            creds_source = "local_file"
            try:
                with open(local_path) as f:
                    cred_dict = json.load(f)
                result["steps"].append({
                    "step": "load_local_file",
                    "success": True,
                    "project_id": cred_dict.get("project_id", "?")
                })
            except Exception as e:
                result["steps"].append({
                    "step": "load_local_file",
                    "success": False,
                    "error": str(e)
                })
                result["error"] = f"Failed to parse local file: {e}"
                return jsonify(result), 500

        elif os.environ.get("FIREBASE_CREDENTIALS"):
            creds_source = "env_single"
            try:
                cred_dict = json.loads(os.environ["FIREBASE_CREDENTIALS"])
                result["steps"].append({
                    "step": "load_env_single",
                    "success": True,
                    "project_id": cred_dict.get("project_id", "?")
                })
            except Exception as e:
                result["steps"].append({
                    "step": "load_env_single",
                    "success": False,
                    "error": str(e)
                })
                result["error"] = f"Failed to parse FIREBASE_CREDENTIALS: {e}"
                return jsonify(result), 500

        elif os.environ.get("FIREBASE_PRIVATE_KEY"):
            creds_source = "env_individual"
            pk = os.environ["FIREBASE_PRIVATE_KEY"].replace("\\n", "\n")
            cred_dict = {
                "type": os.environ.get("FIREBASE_TYPE", "service_account"),
                "project_id": os.environ.get("FIREBASE_PROJECT_ID", ""),
                "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID", ""),
                "private_key": pk,
                "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL", ""),
                "client_id": os.environ.get("FIREBASE_CLIENT_ID", ""),
                "token_uri": os.environ.get("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": (
                    "https://www.googleapis.com/robot/v1/metadata/x509/"
                    + os.environ.get("FIREBASE_CLIENT_EMAIL", "").replace("@", "%40")
                ),
            }
            result["steps"].append({
                "step": "build_from_individual_env_vars",
                "success": True,
                "project_id": cred_dict.get("project_id", "?")
            })

        else:
            result["error"] = (
                "No credentials found. Options:\n"
                "1. Add a Secret File at /etc/secrets/firebase-credentials.json\n"
                "2. Add firebase-credentials.json to the project\n"
                "3. Set FIREBASE_CREDENTIALS env var\n"
                "4. Set FIREBASE_PRIVATE_KEY + FIREBASE_CLIENT_EMAIL + FIREBASE_PROJECT_ID"
            )
            result["steps"].append({"step": "find_credentials", "error": "None found"})
            return jsonify(result), 500

        result["steps"].append({
            "step": "credentials_source",
            "source": creds_source
        })

        # Step 2: Check private key format
        pk = cred_dict.get("private_key", "")
        result["steps"].append({
            "step": "check_private_key",
            "has_begin": "-----BEGIN PRIVATE KEY-----" in pk,
            "has_end": "-----END PRIVATE KEY-----" in pk,
            "length": len(pk)
        })

        # Step 3: Initialize Firebase
        try:
            import firebase_admin
            from firebase_admin import credentials, db

            try:
                existing = firebase_admin.get_app()
                result["steps"].append({
                    "step": "firebase_app",
                    "status": "already_initialized",
                    "name": existing.name
                })
            except ValueError:
                db_url = os.environ.get("FIREBASE_DATABASE_URL") or cred_dict.get("databaseURL")
                if not db_url:
                    result["error"] = "FIREBASE_DATABASE_URL not set"
                    result["steps"].append({"step": "firebase_app", "error": "No database URL"})
                    return jsonify(result), 500

                firebase_admin.initialize_app(
                    credentials.Certificate(cred_dict),
                    {"databaseURL": db_url}
                )
                result["steps"].append({
                    "step": "firebase_app",
                    "status": "initialized_now",
                    "database_url": db_url[:50] + "..."
                })

            # Step 4: Test database read
            ref = db.reference("/")
            kr_tags = ref.child("kr_tags").get()
            users = ref.child("users").get()

            result["steps"].append({
                "step": "db_read",
                "success": True,
                "kr_tags_count": len(kr_tags) if kr_tags else 0,
                "users_count": len(users) if users else 0
            })

            result["success"] = True
            result["message"] = "Firebase is fully operational. Ready to sign up users."

        except Exception as e:
            result["steps"].append({
                "step": "firebase_init_or_db_read",
                "success": False,
                "error": str(e),
                "traceback_tail": traceback.format_exc()[-400:]
            })
            result["error"] = str(e)
            return jsonify(result), 500

        return jsonify(result)

    # ═══════════════════════════════
    # REGISTER BLUEPRINTS
    # ═══════════════════════════════
    blueprint_error = None
    try:
        from auth.routes import auth_bp
        from wallet.routes import wallet_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(wallet_bp)
        print("Blueprints registered successfully.")
    except Exception as e:
        blueprint_error = str(e)
        print(f"WARNING: Blueprint registration failed: {e}")

        @app.route('/api/auth/signup', methods=['POST'])
        def fallback_signup():
            return jsonify({
                "success": False,
                "error": f"Server initialization error: {blueprint_error}. Check /debug/firebase"
            }), 500

        @app.route('/api/auth/login', methods=['POST'])
        def fallback_login():
            return jsonify({
                "success": False,
                "error": f"Server initialization error: {blueprint_error}. Check /debug/firebase"
            }), 500

        @app.route('/api/user/lookup', methods=['POST'])
        @app.route('/api/wallet/balance', methods=['GET'])
        @app.route('/api/wallet/send', methods=['POST'])
        @app.route('/api/wallet/transactions', methods=['GET'])
        def fallback_all():
            return jsonify({
                "success": False,
                "error": f"Server initialization error: {blueprint_error}. Check /debug/firebase"
            }), 500

    # ═══════════════════════════════
    # ERROR HANDLERS
    # ═══════════════════════════════
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "Endpoint not found. Try /debug/status or /debug/firebase"
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({"success": False, "error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"success": False, "error": "Internal server error."}), 500

    return app


app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
