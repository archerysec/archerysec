from django.db.models.signals import post_save
from notifications.signals import notify
from webscanners.models import zap_spider_db


def my_handler(sender, instance, created, **kwargs):
    notify.send(instance, verb='was saved')

post_save.connect(my_handler, sender=zap_spider_db)