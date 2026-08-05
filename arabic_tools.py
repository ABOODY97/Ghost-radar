import arabic_reshaper
from bidi.algorithm import get_display

def fix_ar(text):
    reshaped_text = arabic_reshaper.reshape(text)
    correct_text = get_display(reshaped_text)
    return correct_text
