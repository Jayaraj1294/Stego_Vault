# Generated by Django 5.1.5 on 2025-03-27 01:53

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("Steg_app", "0026_notification"),
    ]

    operations = [
        migrations.AddField(
            model_name="uploadedimage",
            name="user",
            field=models.ForeignKey(
                default="5",
                on_delete=django.db.models.deletion.CASCADE,
                to="Steg_app.userregistration",
            ),
        ),
    ]
