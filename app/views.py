from Podgotovka import rabotnik
from stoi_kripto import *
import skippy
"""
Definition of views.
"""

from datetime import datetime
from django.shortcuts import render
from django.http import HttpRequest

def home(request):
    """Renders the home page."""
    assert isinstance(request, HttpRequest)
    return render(
        request,
        'app/Glavnaya.html',
    )

def rabotaem(request):
    #Шифруем и дешифруем картинку
    if request.method == 'POST':
        RAK = rabotnik()
        list_image = RAK.image_v_bytes(request.FILES.get('photo-upload'))
        old_image = RAK.bytes_to_image(list_image[0],list_image[1],list_image[2], 'old', '1')
        KEY = []
        KEY_temp = request.POST.get('encryption-key').encode('utf8')
        for i in KEY_temp: KEY.append(i)
        if len(KEY) > 10: KEY = RAK.return_key()
        IV = request.POST.get('Salt')
        if IV != '': IV = int(IV)
        encryption_mode = request.POST.get('encryption-mode')
        vibor = request.POST.get('vibor')
        mas_for_skipjack = RAK.delaem_mas_for_SJ(list_image[2])

        skippy_mas = RAK.delaem_mas_for_SJ(list_image[2],'yes')
        skippy_image_bytes = []
        if len(KEY) != 0:cipher = skippy.Skippy(KEY)
        else: cipher = skippy.Skippy(RAK.return_key())
        if encryption_mode == 'ECB' and vibor == 'shifr':
            new_image_bytes = RAK.encrypt_ecb(mas_for_skipjack,KEY)
            new_image = RAK.bytes_to_image(list_image[0],list_image[1],new_image_bytes, 'new')
            #Теперь работаем со Skippy
            for i in skippy_mas:
                 skippy_image_bytes.append(cipher.encrypt(i))
            skippy_image = RAK.bytes_to_image(list_image[0],list_image[1],skippy_image_bytes, 'skippy')
        if encryption_mode == 'ECB' and vibor == 'deshifr':
            new_image_bytes = RAK.decrypt_ecb(mas_for_skipjack,KEY)
            new_image = RAK.bytes_to_image(list_image[0],list_image[1],new_image_bytes, 'new')
        if encryption_mode == 'CBC' and vibor == 'shifr':
            new_image_bytes = RAK.encrypt_cbc(mas_for_skipjack,IV,KEY)
            new_image = RAK.bytes_to_image(list_image[0],list_image[1],new_image_bytes, 'new')
            #Теперь работаем со Skippy
            for i in skippy_mas:
                 skippy_image_bytes.append(cipher.encrypt(i))
            skippy_image = RAK.bytes_to_image(list_image[0],list_image[1],skippy_image_bytes, 'skippy')
        if encryption_mode == 'CBC' and vibor == 'deshifr':
            new_image_bytes = RAK.decrypt_cbc(mas_for_skipjack,IV,KEY)
            new_image = RAK.bytes_to_image(list_image[0],list_image[1],new_image_bytes, 'new')
        
        #Высчитываем коэффициенты
        if vibor == 'shifr':
            res = {}
        
            coefs = calc_coefs_of_correlations(old_image)
            res['src_entropy'] = round(old_image.entropy(),4)
            res['src_covar_h'] = round(coefs['horizontal'], 4)
            res['src_covar_v'] = round(coefs['vertical'], 4)
            res['src_covar_d'] = round(coefs['diagonal'], 4)

            coefs = calc_coefs_of_correlations(new_image)
            res['enc_entropy'] = round(new_image.entropy(),4)
            res['enc_covar_h'] = round(coefs['horizontal'], 4)
            res['enc_covar_v'] = round(coefs['vertical'], 4)
            res['enc_covar_d'] = round(coefs['diagonal'], 4)

            coefs = calc_coefs_of_correlations(skippy_image)
            res['skippy_entropy'] = round(skippy_image.entropy(),4)
            res['skippy_covar_h'] = round(coefs['horizontal'], 4)
            res['skippy_covar_v'] = round(coefs['vertical'], 4)
            res['skippy_covar_d'] = round(coefs['diagonal'], 4)

            changed_pixel_image = get_img_with_changed_random_pixel(old_image)
            changed_pixel_image_bytes = changed_pixel_image.tobytes()
            changed_pixel_image_for_sj = RAK.delaem_mas_for_SJ(changed_pixel_image_bytes)
            
            if encryption_mode == 'ECB':
                changed_pixel_enc_bytes = RAK.encrypt_ecb(changed_pixel_image_for_sj,KEY)
            else:
                changed_pixel_enc_bytes = RAK.encrypt_cbc(changed_pixel_image_for_sj,IV,KEY)
            
            final_bytes_decrypt = b''
            for i in changed_pixel_enc_bytes:
                final_bytes_decrypt += i.to_bytes(8,'big')
            
            changed_pixel_enc = Image.frombytes(changed_pixel_image.mode, changed_pixel_image.size, final_bytes_decrypt)
            changed_pixel_enc_skippy = Image.open('app\\static\\skippy.png')
            
            if changed_pixel_image.mode == "P":
                changed_pixel_enc.putpalette(changed_pixel_image.palette)
                changed_pixel_enc_skippy.putpalette(changed_pixel_image.palette)

            npcr = get_npcr(changed_pixel_enc, new_image)
            uaci = get_uaci(changed_pixel_enc, new_image)
            
            npcr_skippy = get_npcr(changed_pixel_enc_skippy, new_image)
            uaci_skippy = get_uaci(changed_pixel_enc_skippy, new_image)
            
            #Пихаем все коэффициенты в одну переменную для передачи
            context = {
                'cipher_mode': vibor,
                'res_src_entropy': res['src_entropy'],
                'res_src_covar_h': res['src_covar_h'],
                'res_src_covar_v': res['src_covar_v'],
                'res_src_covar_d': res['src_covar_d'],

                'res_enc_entropy': res['enc_entropy'],
                'res_enc_covar_h': res['enc_covar_h'],
                'res_enc_covar_v': res['enc_covar_v'],
                'res_enc_covar_d': res['enc_covar_d'],

                'res_skippy_entropy': res['skippy_entropy'],
                'res_skippy_covar_h': res['skippy_covar_h'],
                'res_skippy_covar_v': res['skippy_covar_v'],
                'res_skippy_covar_d': res['skippy_covar_d'],

                'npcr_label': npcr,
                'uaci_label': uaci,
                'npcr_label_skippy': npcr_skippy,
                'uaci_label_skippy': uaci_skippy,

            }
            return render(request, 'app/final.html', context)
        else:
            context = {
                'cipher_mode': vibor
            }
            return render(request, 'app/final.html', context)
    return render(request, 'app/Glavnaya.html')
        