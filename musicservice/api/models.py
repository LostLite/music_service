from django.db import models

# Create your models here.
class Songs(models.Model):
    title = models.CharField(max_length=255, unique=True, null=False)
    artist = models.CharField(max_length=255, null=False)

    # return a named instance
    def __str__(self):
        return "{} - {}".format(self.title, self.artist)

class TokenBlackList(models.Model):
    token = models.TextField(unique=True)