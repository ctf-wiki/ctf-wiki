[EN](./introduction.md) | [ZH](./introduction-zh.md)
Image files are a good source of hacker culture, so various image files often appear in CTF contests.


Image files come in a variety of complex formats and can be used for a variety of analysis and decryption involving metadata, loss of information and lossless compression, verification, steganography or visual data encoding, all of which are important directions in Misc. . There are a lot of knowledge points (including basic file formats, common steganography and steganography software), and some places need to be deeply understood.


## Metadata (Metadata)


&gt; Metadata, also known as mediation data, relay data, is data about data, mainly information describing the properties of the data, used to support such as storage location, historical data, resources Find, file, and more.


Hidden information in metadata is the most basic method in the game, usually used to hide some key `Hint` information or some important information such as `password`.


You can view this type of metadata by right-clicking on the --&gt; property, or by using the `strings` command. In general, some hidden information (strange strings) often appears in the header or trailer.


Next, we introduce an `identify` command, which is used to get the format and characteristics of one or more image files.


`-format` is used to specify the information displayed, and flexible use of its `-format` parameter can bring a lot of convenience to solving problems. [format specific meaning of each parameter] (https://www.imagemagick.org/script/escape.php)


### Example


[Break In 2017 - Mysterious GIF](https://github.com/ctfs/write-ups-2017/tree/master/breakin-ctf-2017/misc/Mysterious-GIF)



One of the difficulties in this problem is to discover and extract the metadata in the GIF. First, `strings` can observe the abnormal points.


```shell

GIF89a
   !!!"""###$$$%%%&&&'''((()))***+++,,,---...///000111222333444555666777888999:::;;;<<<===>>>???@@@AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPPQQQRRRSSSTTTUUUVVVWWWXXXYYYZZZ[[[\\\]]]^^^___```aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnnooopppqqqrrrssstttuuuvvvwwwxxxyyyzzz{{{|||}}}~~~

4d494945767749424144414e42676b71686b6947397730424151454641415343424b6b776767536c41674541416f4942415144644d4e624c3571565769435172
NETSCAPE2.0

ImageMagick

...

```



The string of hexadecimal here is actually hidden in the metadata area of the GIF.


The next step is extraction, you can choose Python, but it is more convenient to use `identify`


```shell

root in ~/Desktop/tmp λ identify -format "%s %c \n" Question.gif

0 4d494945767749424144414e42676b71686b6947397730424151454641415343424b6b776767536c41674541416f4942415144644d4e624c3571565769435172
1 5832773639712f377933536849507565707478664177525162524f72653330633655772f6f4b3877655a547834346d30414c6f75685634364b63514a6b687271
...

24 484b7735432b667741586c4649746d30396145565458772b787a4c4a623253723667415450574d35715661756278667362356d58482f77443969434c684a536f
25 724b3052485a6b745062457335797444737142486435504646773d3d
```



Other processes are not described here, please refer to the Writeup in the link.


## Pixel value conversion


Look at the data in this file, what can you think of?


```

255,255,255,255,255...........

```



Is a string of RGB values, try to convert him into a picture


```python

from PIL import Image

import re



x = 307 #x coordinates by integer decomposition of the number of lines in txt
y = 311 #ycoordinates x*y = number of rows


rgb1 = [****]
print len (rgb1) / 3
m=0

for i in xrange(0,x):

    for j in xrange(0,y):



Line = rgb1[(3*m):(3*(m+1))]#Get a line
        m+=1

        rgb = line



Im.putpixel((i,j),(int(rgb[0]), int(rgb[1]), int(rgb[2])))#rgb converted to pixels
im.show()

im.save("flag.png")

```



And if the other way around, extract the RGB values from a picture, and then compare the RGB values to get the final flag.


Most of these topics are pictures of some pixel blocks, as shown below.


![](./figure/brainfun.png)



Related topics:


-   [CSAW-2016-quals:Forensic/Barinfun](https://github.com/ctfs/write-ups-2016/tree/master/csaw-ctf-2016-quals/forensics/brainfun-50)

-   [breakin-ctf-2017:A-dance-partner](https://github.com/ctfs/write-ups-2017/tree/master/breakin-ctf-2017/misc/A-dance-partner)
