# Generated by Django 5.1.3 on 2024-12-06 07:01

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DSA', '0010_studentperformance_alter_otp_expired_at'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='StudentPerformance',
            new_name='StudentResult',
        ),
        migrations.AlterField(
            model_name='otp',
            name='expired_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 6, 7, 6, 44, 567506, tzinfo=datetime.timezone.utc)),
        ),
    ]
