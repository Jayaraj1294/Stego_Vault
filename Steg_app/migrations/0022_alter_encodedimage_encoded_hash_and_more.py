# Generated by Django 5.1.5 on 2025-03-24 06:40

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("Steg_app", "0021_tamperingdetection_encoded_image_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="encodedimage",
            name="encoded_hash",
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
        migrations.AlterField(
            model_name="tamperingdetection",
            name="tampering_check_hash",
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
        migrations.AlterField(
            model_name="uploadedimage",
            name="original_hash",
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
        migrations.AlterField(
            model_name="watermarkkey",
            name="watermarked_hash",
            field=models.CharField(blank=True, max_length=256, null=True),
        ),
    ]
