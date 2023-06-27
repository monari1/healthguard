from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UserProfileManager(BaseUserManager):
    def create_user(self, username, password=None):
        if not username:
            raise ValueError('Username is required')
        
        username = self.normalize_username(username)
        user = self.model(username=username)
        user.set_password(password)
        user.save(using=self._db)
        
        return user

    def create_superuser(self, username, password):
        user = self.create_user(username, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        
        return user

class UserProfile(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255, blank=True)
    last_name = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    
    objects = UserProfileManager()
    
    USERNAME_FIELD = 'username'
    
    def __str__(self):
        return self.username




""" A topic the user is learning about """
class Name(models.Model):
    text = models.CharField(max_length= 200)
    date_added = models.DateTimeField(auto_now_add=True )
    def __str__(self):
        """ Return  a string representation of the model """
        return self.text
