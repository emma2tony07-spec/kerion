import os
import sys
import traceback
from flask import Flask, jsonify, request
from flask_cors import CORS

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Enable CORS for all routes
    CORS(app, resources={r"/api/*": {"origins": "*"}, r"/debug/*": {"origins": "*"}})
    
    # ═══════════════════════════════
    # HEALTH CHECK
    # ═══════════════════════════════
    @app.route('/')
    def home():
        return jsonify({
            "status": "ok",
            "app": "Kerion Wallet API",
            "version": "1.0.1"
        })
    
    @app.route('/health')
    def health():
        return jsonify({"status": "healthy"}), 200
    
    # ═══════════════════════════════
    # DEBUG ENDPOINTS
    # ═══════════════════════════════
    @app.route('/debug/env', methods=['GET'])
    def debug_env():
        """Check which environment variables are set (values hidden for security)."""
        vars_to_check = [
            'FIREBASE_CREDENTIALS',
            'FIREBASE_DATABASE_URL',
            'FIREBASE_API_KEY',
            'PORT'
        ]
        result = {}
        for var in vars_to_check:
            val = os.environ.get(var)
            if val:
                # Show first 30 chars only for security
                result[var] = f"SET (starts with: {val[:30]}...)"
            else:
                result[var] = "NOT SET"
        return jsonify({"success": True, "environment": result})
    
    @app.route('/debug/firebase', methods=['GET'])
    def debug_firebase():
        """Test Firebase initialization step by step."""
        steps = []
        
        # Step 1: Check environment
        creds_set = bool(os.environ.get('FIREBASE_CREDENTIALS'))
        db_url_set = bool(os.environ.get('FIREBASE_DATABASE_URL'))
        steps.append({
            "step": "environment",
            "credentials_set": creds_set,
            "database_url_set": db_url_set
        })
        
        if not creds_set:
            return jsonify({
                "success": False,
                "error": "FIREBASE_CREDENTIALS not set",
                "steps": steps
            }), 500
        
        if not db_url_set:
            return jsonify({
                "success": False,
                "error": "FIREBASE_DATABASE_URL not set",
                "steps": steps
            }), 500
        
        # Step 2: Try parsing credentials
        try:
            import json
            creds_str = os.environ.get('FIREBASE_CREDENTIALS')
            creds_dict = json.loads(creds_str)
            steps.append({
                "step": "parse_credentials",
                "success": True,
                "project_id": creds_dict.get('project_id', 'NOT FOUND'),
                "client_email": creds_dict.get('client_email', 'NOT FOUND')[:40] + '...',
                "has_private_key": 'private_key' in creds_dict
            })
        except json.JSONDecodeError as e:
            steps.append({
                "step": "parse_credentials",
                "success": False,
                "error": f"Invalid JSON: {str(e)}",
                "first_100_chars": creds_str[:100] if creds_set else "N/A"
            })
            return jsonify({
                "success": False,
                "error": "FIREBASE_CREDENTIALS is not valid JSON",
                "steps": steps
            }), 500
        
        # Step 3: Try initializing Firebase
        try:
            import firebase_admin
            from firebase_admin import credentials, db
            
            # Check if already initialized
            try:
                app_obj = firebase_admin.get_app()
                steps.append({
                    "step": "firebase_init",
                    "already_initialized": True,
                    "app_name": app_obj.name
                })
            except ValueError:
                # Not initialized - do it now
                cred = credentials.Certificate(creds_dict)
                database_url = os.environ.get('FIREBASE_DATABASE_URL')
                
                firebase_admin.initialize_app(cred, {
                    'databaseURL': database_url
                })
                steps.append({
                    "step": "firebase_init",
                    "already_initialized": False,
                    "initialized_now": True,
                    "database_url": database_url
                })
        except Exception as e:
            steps.append({
                "step": "firebase_init",
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            })
            return jsonify({
                "success": False,
                "error": f"Firebase init failed: {str(e)}",
                "steps": steps
            }), 500
        
        # Step 4: Try reading from DB
        try:
            ref = db.reference('/')
            kr_tags = ref.child('kr_tags').get()
            steps.append({
                "step": "db_read",
                "success": True,
                "kr_tags": kr_tags,
                "kr_tags_type": str(type(kr_tags))
            })
        except Exception as e:
            steps.append({
                "step": "db_read",
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            })
            return jsonify({
                "success": False,
                "error": f"Database read failed: {str(e)}",
                "steps": steps
            }), 500
        
        return jsonify({
            "success": True,
            "message": "Firebase is fully working",
            "steps": steps
        })
    
    @app.route('/debug/signup-test', methods=['GET'])
    def debug_signup_test():
        """Simulate kr_tag generation without creating a user."""
        try:
            import random
            import string
            from firebase_admin import db
            
            kr_tags_ref = db.reference('kr_tags')
            
            # Generate 5 test tags and check Firebase
            results = []
            for i in range(5):
                digits = ''.join(random.choices(string.digits, k=10))
                kr_tag = f"kr-{digits}"
                
                try:
                    existing = kr_tags_ref.child(kr_tag).get()
                    results.append({
                        "tag": kr_tag,
                        "exists": existing is not None,
                        "existing_uid": existing if existing else None
                    })
                except Exception as e:
                    results.append({
                        "tag": kr_tag,
                        "error": str(e)
                    })
            
            # Try to read the entire kr_tags node
            all_tags = kr_tags_ref.get()
            
            return jsonify({
                "success": True,
                "test_tags": results,
                "all_existing_tags": all_tags,
                "existing_count": len(all_tags) if all_tags else 0
            })
        except Exception as e:
            return jsonify({
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }), 500
    
    # ═══════════════════════════════
    # TRY TO IMPORT AND REGISTER BLUEPRINTS
    # ═══════════════════════════════
    try:
        from auth.routes import auth_bp
        from wallet.routes import wallet_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(wallet_bp)
        print("Blueprints registered successfully.")
    except Exception as e:
        print(f"WARNING: Could not register blueprints: {e}")
        traceback.print_exc()
        
        # Create fallback routes so API doesn't 404
        @app.route('/api/auth/signup', methods=['POST'])
        def fallback_signup():
            return jsonify({
                "success": False,
                "error": f"Server initialization error. Check /debug/firebase. Details: {str(e)}"
            }), 500
        
        @app.route('/api/auth/login', methods=['POST'])
        def fallback_login():
            return jsonify({
                "success": False,
                "error": f"Server initialization error. Check /debug/firebase. Details: {str(e)}"
            }), 500
    
    # ═══════════════════════════════
    # ERROR HANDLERS
    # ═══════════════════════════════
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "Endpoint not found. Available: /debug/env, /debug/firebase, /debug/signup-test, /api/auth/signup, /api/auth/login, /api/wallet/*"
        }), 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({
            "success": False,
            "error": "Method not allowed."
        }), 405
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "success": False,
            "error": f"Internal server error: {str(error)}"
        }), 500
    
    return app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
