# Generated by Django 5.1.3 on 2024-12-05 09:38

import datetime
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('DSA', '0005_customuser_bio_customuser_links_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='expired_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 12, 5, 9, 43, 24, 453226, tzinfo=datetime.timezone.utc)),
        ),
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('certificate_file', models.FileField(upload_to='certificates/')),
                ('uploaded_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]