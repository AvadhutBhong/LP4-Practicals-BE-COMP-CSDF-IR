import random 
import string
import time
from PIL import Image, ImageDraw, ImageFont   # Pillow library used for creating and editing images

def generatecaptcha(length, width=240, height=90, bgcolor=(0, 0, 0),
                    font_path=None, font_size=36, noise_lines=5, noise_dots=120):

    random.seed(time.time())   # initializes random generator with current time to make results unpredictable

    # generate a random alphanumeric string (uppercase letters + digits)
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

    # create a blank image (canvas) of given size and background color
    image = Image.new('RGB', (width, height), bgcolor)
    draw = ImageDraw.Draw(image)   # creates a drawing object for writing text, lines, dots, etc.

    try:
        # try loading a custom or default font; if not found, fall back to default
        font = ImageFont.truetype(font_path or "arial.ttf", font_size)
    except Exception:
        font = ImageFont.load_default()

    # draw random background lines to introduce noise
    # noise helps prevent bots from easily detecting text
    line_color = (200, 200, 200) if sum(bgcolor) > 200 else (80, 80, 80)
    for _ in range(noise_lines):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line(((x1, y1), (x2, y2)), fill=line_color, width=1)

    # calculate spacing between characters dynamically based on image width and captcha length
    spacing = max(20, (width - 40) // max(1, length))
    for i, ch in enumerate(captcha_text):
        # random y position for slight uneven alignment (adds distortion)
        x = 20 + i * spacing
        y = random.randint(10, max(10, height - font_size - 10))

        # select text color based on background brightness
        if sum(bgcolor) < 200:
            text_fill = (255, 255, 255)   # light text for dark background
        else:
            text_fill = (0, 0, 0)         # dark text for light background

        # apply slight random variation in text color
        text_fill = tuple(min(255, max(0, c + random.randint(-30, 30))) for c in text_fill)

        # draw text (each character) on the image
        draw.text((x, y), ch, fill=text_fill, font=font)

    # add small random dots to further increase image complexity
    dot_color = (150,150,150) if sum(bgcolor) > 200 else (80,80,80)
    for _ in range(noise_dots):
        x, y = random.randint(0, width-1), random.randint(0, height-1)
        draw.point((x, y), fill=dot_color)

    # save captcha image as PNG and display it using system viewer
    image.save("captcha.png")
    try:
        image.show()
    except Exception:
        pass

    # return generated text for later comparison
    return captcha_text


def checkcaptcha(generated, entered):
    # compares generated captcha with user input (ignoring extra spaces)
    return generated.strip() == entered.strip()


def main():
    # take captcha length from user
    length = int(input("Enter CAPTCHA length: "))
    captcha_text = generatecaptcha(length)   # generate captcha image

    # ask user to enter visible captcha
    user_input = input("Enter the CAPTCHA text you see: ").strip()

    # compare entered and generated values
    if checkcaptcha(captcha_text, user_input):
        print("CAPTCHA verified successfully!")
    else:
        print("CAPTCHA verification failed!")


if __name__ == "__main__":
    main()



"""
Theory:

A CAPTCHA (Completely Automated Public Turing test to tell Computers and Humans Apart)
is a security mechanism used to distinguish between human users and automated bots.
It is commonly used on websites and applications to prevent automated form submissions,
spam accounts, and brute-force login attempts.

This program demonstrates the generation and verification of a CAPTCHA image using Python’s Pillow library.

Working:
1. The program first generates a random combination of uppercase letters and digits.
2. A new image canvas is created with specified dimensions and background color.
3. Random noise in the form of lines and dots is added to the image to make it hard for OCR
   (Optical Character Recognition) systems to read the characters easily.
4. Each character is drawn at slightly random positions and with slight color variations.
   This randomness ensures that every generated CAPTCHA is unique and difficult for bots to decode.
5. The image is then saved and displayed to the user.
6. The user is asked to manually input the text shown in the image.
7. The input is compared with the originally generated CAPTCHA text for verification.

Important Concepts:
- Random number generation (for text, color, and noise) using the random module.
- String operations using string.ascii_uppercase and string.digits.
- Image creation and modification using the Pillow library (Image, ImageDraw, ImageFont).
- Font handling, color contrast, and positioning.
- Simple input/output and string comparison for verification.

Applications:
CAPTCHA systems are used in login pages, sign-up forms, and online polls
to ensure that only human users perform certain actions. They act as a barrier
against bots that try to exploit web services by automating requests.

Enhancements:
This basic CAPTCHA can be made more secure by adding:
- Text rotation, warping, or distortion.
- Colored backgrounds or gradient patterns.
- Complex shapes or overlay patterns.
- Audio CAPTCHA for accessibility.

This experiment helps understand the concept of visual security, randomness,
and basic image processing using Python.
"""
