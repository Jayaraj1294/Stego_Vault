from django.urls import path
from . import views

urlpatterns=[

    # Landing page urls
    path('',views.home,name="home"),
    path('index/',views.index,name="index"),
    path('Terms/',views.Terms,name="Terms"),
    path('Privacy/',views.Privacy,name="Privacy"),
    path('contact/', views.contact, name="contact"),

    # login urls
    path('log/',views.log,name="log"),

    # Register urls
    path('reg/',views.reg,name="reg"),

    # Forgot urls
    path('forgot/',views.forgot,name="forgot"),

    # Reset urls
    path('reset/<int:user_id>/',views.reset,name="reset"),

    # Logout urls
    path('logout_view/',views.logout_view,name="logout_view"),

    # Dashboard urls
    path('base/',views.base,name="base"),
    path('mark_all_as_read/', views.mark_all_as_read, name="mark_all_as_read"),
    path('dash/',views.dash,name="dash"),

    # Profile urls
    path('profile/',views.profile,name="profile"),
    path('update_username/',views.update_username,name="update_username"),
    path('update_email/',views.update_email,name="update_email"),
    path('update_password/',views.update_password,name="update_password"),
    path('delete_account/', views.delete_account, name='delete_account'),
    path('update_profile_picture/', views.update_profile_picture, name='update_profile_picture'),

    # Steganography urls
    path('steg/',views.steg,name="steg"),
    path('steganalysis/',views.steganalysis,name="steganalysis"),

    # Cryptography urls
    path('Encrypt/',views.Encrypt,name="Encrypt"),
    path('DownloadCiphertext/<int:enc_id>/', views.DownloadCiphertext, name='DownloadCiphertext'),
    path('Decrypt/',views.Decrypt,name="Decrypt"),

    # Watermarking urls
    path('Watermark/',views.Watermark,name="Watermark"),
    path('download-watermarked/<int:image_id>/', views.download_watermarked_image, name='download_watermarked'),
    # path('ExtractWatermark/',views.ExtractWatermark,name="ExtractWatermark"),

    # Tampering urls
    path('Tamper/',views.Tamper,name="Tamper"),

    # Guide urls
    path('Guide/',views.Guide,name="Guide"),
    path('Support/', views.Support, name="Support"),
     path("delete-account/",views.delete_account, name="delete_account"),
    path("check-password/",views.profilecheck_password, name="profilecheck_password"), 
]