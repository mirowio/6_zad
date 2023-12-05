import PIL.Image as Image
from SJ import *

class rabotnik():
    def __init__(self):
        self.sj = SkipJack()
        self.IV = 0
        KEY = ['0x00', '0x99', '0x88', '0x77', '0x66', '0x55', '0x44', '0x33', '0x22', '0x11']
        self.KEY = list(map(lambda x: int(str(x),16),KEY))
    #Возвращаем значение ключа(KEY)
    def return_key(self):
        return self.KEY
    #Преобразование картинки в байты
    def image_v_bytes(self, path):
        image = Image.open(path).convert('RGB')
        mod = image.mode #эта переменная понадобится нам для обратного преобразования
        size = image.size #эта переменная понадобится нам для обратного преобразования
        img_bytes = image.tobytes()
        return [mod,size,img_bytes]

    #Создаём массив 64-битных значений в 16-м формате из байтов
    def delaem_mas_for_SJ(self, img_bytes, skippy='no'):
        if skippy=='no': teshka = 8 
        else: teshka = 4
        mas_for_skipjack = []
        for i in range(0,int(len(img_bytes)/teshka)):
            t1 = i*teshka
            t2 = (i+1)*teshka
            if skippy=='no': mas_for_skipjack.append(bytes.hex(img_bytes[t1:t2]))
            else: mas_for_skipjack.append(int('0x'+bytes.hex(img_bytes[t1:t2]),16))
        return mas_for_skipjack

    #Шифруем наши байты по режиму EBC
    def encrypt_ecb(self, mas_for_skipjack, KEY=None):
        if KEY == None or len(KEY) == 0: KEY = self.KEY
        encrypt_outof_skipjack = []
        for i in mas_for_skipjack:
            PT = int('0x'+ i,16)
            encrypt_outof_skipjack.append(self.sj.encrypt(PT, KEY))
        return encrypt_outof_skipjack

    #Дешифруем наши байты по режиму EBC
    def decrypt_ecb(self, encrypt_outof_skipjack, KEY=None):
        if KEY == None or len(KEY) == 0: KEY = self.KEY
        decrypt_outof_skipjack = []
        for i in encrypt_outof_skipjack:
            PT = int('0x'+ i,16)
            decrypt_outof_skipjack.append(self.sj.decrypt(PT, KEY))
        return decrypt_outof_skipjack

    #Шифруем наши байты в режимем CBC
    def encrypt_cbc(self, mas_for_skipjack, IV=None, KEY=None):
        if IV == None or IV == '': IV = self.IV
        if KEY == None or len(KEY) == 0: KEY = self.KEY
        encrypt_outof_skipjack = []
        for i in mas_for_skipjack:
            PT = int('0x'+ i,16)^IV
            shifr_block = self.sj.encrypt(PT, KEY)
            encrypt_outof_skipjack.append(shifr_block)
            IV = shifr_block
        return encrypt_outof_skipjack

    #Дешифруем наши байты в режимем CBC
    def decrypt_cbc(self, encrypt_outof_skipjack,IV=None, KEY=None):
        if IV == None or IV == '': IV = self.IV
        if KEY == None or len(KEY) == 0: KEY = self.KEY
        decrypt_outof_skipjack = []
        for i in encrypt_outof_skipjack:
            PT = int('0x'+ i,16)
            decrypt_outof_skipjack.append(self.sj.decrypt(PT, KEY)^IV)
            IV = PT
        return decrypt_outof_skipjack


    #Преобразовываем байты обратно в картинку
    def bytes_to_image(self, mod, size, outof_skipjack, name,save='0'):
        final_bytes_decrypt = outof_skipjack
        if save =='0':
            final_bytes_decrypt = b''
            for i in outof_skipjack:
                final_bytes_decrypt += i.to_bytes(8,'big')
        image = Image.frombytes(mod,size,final_bytes_decrypt)
        image.save(f'app\\static\\{name}.png')
        return image