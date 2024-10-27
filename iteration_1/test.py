from flask_bcrypt import Bcrypt

b = Bcrypt()
print(b.generate_password_hash('123'))

from email_validator import validate_email
print(validate_email('faz@l.d'))