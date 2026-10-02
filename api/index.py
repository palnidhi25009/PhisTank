import os
import sys

# Ensure deployment and features directories are added to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "deployment"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "features"))

from app import app
