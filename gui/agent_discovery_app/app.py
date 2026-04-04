from pathlib import Path
import sys
from flask import Flask

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from routes.main_routes import main_bp


def create_app():
    app = Flask(__name__)
    app.register_blueprint(main_bp)
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)