# Generated by Django 5.1.3 on 2024-12-06 08:28

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DSA', '0013_alter_otp_expired_at'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='studentresult',
            name='total',
        ),
        migrations.AlterField(
            model_name='otp',
            name='expired_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 6, 8, 33, 13, 263527, tzinfo=datetime.timezone.utc)),
        ),
    ]