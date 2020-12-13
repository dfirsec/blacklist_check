
from pathlib import Path
from configparser import ConfigParser


parent = Path(__file__).resolve().parent
settings = parent.joinpath('utils/settings.cfg')

config = ConfigParser()
config.read(settings)
                
print(config.get('virus-total', 'api_key'))