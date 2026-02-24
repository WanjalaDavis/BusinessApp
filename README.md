If the database fails do this:

pip uninstall django

pip install "django>=4.2,<5.0"
 
Then run the migrations 

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'monero_db',       
        'USER': 'root',            
        'PASSWORD': '',            
        'HOST': '127.0.0.1',       
        'PORT': '3306',            
    }
}

cd BusinessApp
git pull origin main
