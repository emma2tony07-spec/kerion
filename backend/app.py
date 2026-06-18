import os
from flask import Flask, jsonify
from flask_cors import CORS

from auth.routes import auth_bp
from wallet.routes import wallet_bp

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Enable CORS for all routes (your HTML frontend will need this)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(wallet_bp)
    
    # Health check endpoint (Render uses this)
    @app.route('/')
    def home():
        return jsonify({
            "status": "ok",
            "app": "Kerion Wallet API",
            "version": "1.0.0"
        })
    
    @app.route('/health')
    def health():
        return jsonify({"status": "healthy"}), 200
    
    # Global error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "error": "Endpoint not found."
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
            "error": "Internal server error. Please try again later."
        }), 500
    
    return app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    # For local development
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)