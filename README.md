<div align="center">

<a href="https://ctf-wiki.org/static/img/logo.png" target="_blank"><img src="https://ctf-wiki.org/static/img/logo.png" width="128" height="128"></a>

# CTF Wiki

<p align="center">

Come and join us, we need you!

[![](https://img.shields.io/discord/1115906685450596435?style=for-the-badge&color=%237289DA&label=Discord&logo=discord&logoColor=white")](https://discord.gg/ekv7WDa9pq)  [![](https://img.shields.io/github/stars/CTF-Wiki/CTF-Wiki?style=for-the-badge&color=black&label=Stars&logo=github&logoColor=white")](https://github.com/CTF-Wiki/CTF-Wiki/stargazers)

</p>

</div>

## Introduction

[中文](./README-zh_CN.md)  [English](./README.md)

Welcome to **CTF Wiki**！

**CTF** (Capture The Flag) started from **DEFCON CTF**, a competitive game among computer security enthusiasts, originally hosted in 1996.

**CTF** covers a wide range of fields. Along with the evolving security technology, the difficulty of **CTF** challenges is getting harder and harder. As a result, the learning curve for beginners is getting steeper. Most online information is scattered and trivial. Beginners often don't know how to systematically learn **CTF**, which requires a lot of work and effort.

In order to let those people who are interested in **CTF**s start easily, in October 2016, **CTF Wiki** was established on Github. Along with gradually improved content over time, **CTF Wiki** has received lots of appreciation from security enthusiasts, many of those are guys that we think we would never meet.

As a freedom site, primarily focusing on recent CTFs, **CTF Wiki** introduces the knowledge and techniques in all aspects of **CTF** to make it easier for beginners to learn **CTF**.

Now, **CTF Wiki** mainly contains the basic skills for **CTF**, but we are working hard to improve the following contents.

- Advanced skills used in CTF
- Special topics appearing in CTF

For the above-mentioned parts to be improved, please refer to [Projects](https://github.com/ctf-wiki/ctf-wiki/projects) which details what are planned.

Although now **CTF Wiki** mainly focus **CTF**, it is not strictly limited to **CTF** topics. In the future, **CTF Wiki** will include

- Tools used in security research
- Increased discussion of security in the world

In addition, given the following two points

- Information about technology should be openly shared.
- As new techniques are always being developed, old techniques will start to fade over time and they should be replaced with new techniques.

Therefore, **CTF Wiki** will never publish books.

Finally, originating from the community, as an independent organization, **CTF Wiki** advocates **freedom of knowledge**, will **never be commercialized**, and will always maintain the character of **independence and freedom**.

## How to build？

CTF Wiki uses [mkdocs](https://github.com/mkdocs/mkdocs) to show its contents. And it is deployed at [https://ctf-wiki.org](https://ctf-wiki.org).

It can also be deployed locally, with the following steps:

```shell
# 1. clone
git clone https://github.com/ctf-wiki/ctf-wiki.git
# 2. requirements
pip install -r requirements.txt
# generate static file in site/
python3 scripts/docs.py build-all
# deploy at http://127.0.0.1:8008
python3 scripts/docs.py serve
```

**A local instance of mkdocs is dynamically updated, for instance when a markdown file is modified, the corresponding page will be modified too.**

If you just want to view it statically, try Docker!

```
docker run -d --name=ctf-wiki -p 4100:80 ctfwiki/ctf-wiki
```
And then access [http://localhost:4100/](http://localhost:4100/) .

## How to practice？

Firstly, learn some basic security knowledge through online reading.

Secondly, CTF Wiki has two sister projects.

- All of the challenges that are mentioned are in the [ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) repository, you can locate them with their corresponding category.
- The tools mentioned in the CTF Wiki are constantly added to the [ctf-tools](https://github.com/ctf-wiki/ctf-tools) repository.

## How to make CTF Wiki Better？

We welcome to write content for the wiki and share what you have learned. 

**Before you decide to contribute content, please read [CONTRIBUTING](https://ctf-wiki.org/en/contribute/before-contributing/)**.

Thank you to all the people who have already contributed to CTF Wiki.

<a href="https://github.com/ctf-wiki/ctf-wiki/graphs/contributors"><img src="https://contrib.rocks/image?repo=ctf-wiki/ctf-wiki" /></a>

## What can you get?

- Ability to learn new things quickly
- Different ways of thinking
- A love for solving problems
- Interesting security techniques
- Memorable and enriching experience

Before reading the Wiki, we hope to give you some advice:

- Learn to ask [smart-questions](http://www.catb.org/~esr/faqs/smart-questions.html) .
- Learn to use Google Search for self-improvement.
- Be good at least one programming language, such as Python.
- Practice is the most important learning tool.
- Maintain the passions and desire to learn about new techniques.

The security circle is small and the areas of exploration is vast. Let's get started with **CTF Wiki**!


## 🌐 Web Resources & Interactive Index
- [CATEGORY ART32](https://themindplays.pages.dev/category-art32.html)
- [TIMEWALKER SURVIVE](https://theskillquest.pages.dev/timewalker-survive.html)
- [CATEGORY ADVENTURE](https://thequizzone.pages.dev/category-adventure.html)
- [CUT IN HALF](https://ilearnworldjp.pages.dev/cut-in-half.html)
- [EMOJI SMASHER SMILEY GAME](https://theskillquest.pages.dev/emoji-smasher-smiley-game.html)
- [AQUA SORT WATER COLOR PUZZLE](https://theskillquest.pages.dev/aqua-sort-water-color-puzzle.html)
- [DART HERO](https://theskillquest.pages.dev/dart-hero.html)
- [CATEGORY HUB](https://thequizzone.pages.dev/category-hub.html)
- [SNAKE PUZZLE ESCAPE](https://thelearnquesters.pages.dev/snake-puzzle-escape.html)
- [SLIDE BLOCK PUZZLE](https://theskillquest.pages.dev/slide-block-puzzle.html)
- [PHYSICS BALLS](https://theskillquest.pages.dev/physics-balls.html)
- [FIND THE SPRUNKI](https://theskillquest.pages.dev/find-the-sprunki.html)
- [WORD SEARCH UNIVERSE 2](https://theskillquest.pages.dev/word-search-universe-2.html)
- [FIND RESTORE HIDDEN PUZZLE](https://thelearnquesters.pages.dev/find-restore-hidden-puzzle.html)
- [MERGE WAR](https://theskillquest.pages.dev/merge-war.html)
- [HAPPY FARM THE CROP](https://thelearnquesters.pages.dev/happy-farm-the-crop.html)
- [FURY OF THE STEAMPUNK PRINCESS](https://thelearnquesters.pages.dev/fury-of-the-steampunk-princess.html)
- [ISLAND EXPANDER](https://theskillquest.pages.dev/island-expander.html)
- [GRAND CLASH ARENA](https://thequizzone.pages.dev/grand-clash-arena.html)
- [AIDAN IN DANGER](https://theskillquest.pages.dev/aidan-in-danger.html)
- [CATEGORY MAKEUP51](https://thequizzone.pages.dev/category-makeup51.html)
- [RIDDLEMATH](https://theskillquest.pages.dev/riddlemath.html)
- [WIRE CONNECT](https://thequizzone.pages.dev/wire-connect.html)
- [HILL CLIMB TRUCK TRANSFORM ADVENTURE](https://thelearnquesters.pages.dev/hill-climb-truck-transform-adventure.html)
- [CATEGORY BASKETBALL 3](https://iskillquest.pages.dev/category-basketball-3.html)
- [US ARMY CAR GAMES TRUCK DRIVING](https://theskillquest.pages.dev/us-army-car-games-truck-driving.html)
- [CATEGORY GUN241](https://thelearnquesters.pages.dev/category-gun241.html)
- [TUNNEL ROAD](https://thequizzone.pages.dev/tunnel-road.html)
- [RACE CLICKER](https://theskillquest.pages.dev/race-clicker.html)
- [LOVIE CHICS COACHELLA FESTIVAL](https://thequizzone.pages.dev/lovie-chics-coachella-festival.html)
- [IDLE ANIMAL ANATOMY](https://theskillquest.pages.dev/idle-animal-anatomy.html)
- [CATEGORY GUN238](https://thelearnquesters.pages.dev/category-gun238.html)
- [SQUID CANDY CHALLENGE](https://thequizzone.pages.dev/squid-candy-challenge.html)
- [PIRATE ISLAND](https://theskillquest.pages.dev/pirate-island.html)
- [FASHION CHALLENGE CATWALK RUN](https://theskillquest.pages.dev/fashion-challenge-catwalk-run.html)
- [ASMR GIRL LIVESTREAM MUKBANG](https://theskillquest.pages.dev/asmr-girl-livestream-mukbang.html)
- [WORM OUT BRAIN TEASER GAMES](https://thequizzone.pages.dev/worm-out-brain-teaser-games.html)
- [BLOCK UP](https://theskillquest.pages.dev/block-up.html)
- [TILE FARM STORY MATCHING GAME](https://theskillquest.pages.dev/tile-farm-story-matching-game.html)
- [CATEGORY BUILDING182](https://iskillquest.pages.dev/category-building182.html)
- [BOOM STICK BAZOOKA](https://theskillquest.pages.dev/boom-stick-bazooka.html)
- [PESKY MOLES](https://theskillquest.pages.dev/pesky-moles.html)
- [WACKY STRIKE](https://thelearnquesters.pages.dev/wacky-strike.html)
- [MASTER BLENDER](https://themindzone.pages.dev/master-blender.html)
- [CATEGORY PUZZLE 8](https://theskillquest.pages.dev/category-puzzle-8.html)
- [CATEGORY UNBLOCKER](https://thequizzone.pages.dev/category-unblocker.html)
- [CATEGORY ANIMAL216](https://theskillquest.pages.dev/category-animal216.html)
- [LOAD THE DISHES ASMR](https://theskillquest.pages.dev/load-the-dishes-asmr.html)
- [GLITCH](https://themindzone.pages.dev/glitch.html)
- [CATEGORY BATTLE ROYALE](https://theskillquest.pages.dev/category-battle-royale.html)
- [CATEGORY MERGE](https://themindplay.github.io/category-merge.html)
- [CARDS KLONDIKE SOLITAIRE](https://themindplays.pages.dev/cards-klondike-solitaire.html)
- [BRAINROT MOB CLASH 3D](https://themindplay.pages.dev/brainrot-mob-clash-3d.html)
- [SID GINNY Y2K GLAM CLASH](https://themindzone.pages.dev/sid-ginny-y2k-glam-clash.html)
- [CATEGORY CAR](https://themindplaying.web.app/category-car.html)
- [CATEGORY MAKEUP51](https://thelearnquesters.pages.dev/category-makeup51.html)
- [STYLISH NAIL ART](https://themindplay.pages.dev/stylish-nail-art.html)
- [PICTURE PUZZLES](https://themindplay.pages.dev/picture-puzzles.html)
- [FRUIT KING MERGE](https://themindplay.pages.dev/fruit-king-merge.html)
- [ARMY FIGHT 3D](https://themindplay.pages.dev/army-fight-3d.html)
- [CUBE SPEED DASH](https://themindplay.github.io/cube-speed-dash.html)
- [CATEGORY ARENA254](https://theskillquest.pages.dev/category-arena254.html)
- [SKILLFUL FINGER](https://themindzone.pages.dev/skillful-finger.html)
- [SNAKE PUZZLE SLITHER TO EAT](https://themindplay.pages.dev/snake-puzzle-slither-to-eat.html)
- [VEGAMIX DA VINCI PUZZLES](https://themindzone.pages.dev/vegamix-da-vinci-puzzles.html)
- [CROCODILO TRALALERO RUN](https://themindplay.pages.dev/crocodilo-tralalero-run.html)
- [HERO RAGDOLL FIGHTING](https://thelearnquesters.pages.dev/hero-ragdoll-fighting.html)
- [BALL EATING SIMULATOR](https://theskillquest.pages.dev/ball-eating-simulator.html)
- [MOW IT](https://thelearnquesters.pages.dev/mow-it.html)
- [BRAINROT BOING BOING MERGE](https://themindplay.pages.dev/brainrot-boing-boing-merge.html)
- [STICKMAN ADVENTURE](https://theskillquest.pages.dev/stickman-adventure.html)
- [CATEGORY BIKE 2](https://iskillquest.pages.dev/category-bike-2.html)
- [HIDE AND ESCAPE FROM ANGRY TEACHER](https://theskillquest.pages.dev/hide-and-escape-from-angry-teacher.html)
- [SNAKE CLASH](https://themindplay.github.io/snake-clash.html)
- [CATEGORY MINECRAFT](https://themindplay.pages.dev/category-minecraft.html)
- [BALLISTIC BREAKTHROUGH](https://themindzone.pages.dev/ballistic-breakthrough.html)
- [CATEGORY MOUSE1 697](https://theskillquest.pages.dev/category-mouse1-697.html)
- [GRUNGE CHIC ALT FASHION](https://themindplay.pages.dev/grunge-chic-alt-fashion.html)
- [99 BALLS](https://themindplay.pages.dev/99-balls.html)
- [LOL SURPRISE OMG BB DRIVER](https://thequizzone.pages.dev/lol-surprise-omg-bb-driver.html)
- [CATEGORY BATTLE](https://theskillquest.pages.dev/category-battle.html)
- [HIDDEN OBJECT MY HOTEL](https://themindplay.pages.dev/hidden-object-my-hotel.html)
- [U SHAPE PUZZLE](https://themindplay.pages.dev/u-shape-puzzle.html)
- [PUZZLE MASTERS TRAVELERS](https://theskillquest.pages.dev/puzzle-masters-travelers.html)
- [BARBEE MET GALA TRANSFORMATION](https://themindplay.pages.dev/barbee-met-gala-transformation.html)
- [DOGE RUSH DRAW HOME PUZZLE](https://thequizzone.pages.dev/doge-rush-draw-home-puzzle.html)
- [FURRY WEDDING PROPOSAL](https://themindplay.pages.dev/furry-wedding-proposal.html)
- [XMAS PRESENTS MAHJONG](https://theskillquest.pages.dev/xmas-presents-mahjong.html)
- [CARS MERGE](https://thequizzone.pages.dev/cars-merge.html)
- [ANIMAL SWIPE](https://thelearnquesters.pages.dev/animal-swipe.html)
- [BOTTLE CHALLENGE](https://themindzone.pages.dev/bottle-challenge.html)
- [SEEK FIND](https://themindplay.pages.dev/seek-find.html)
- [CATEGORY MINECRAFT 2](https://themindplay.pages.dev/category-minecraft-2.html)
- [NITRO SPEED 2 UNDERGROUND](https://thequizzone.pages.dev/nitro-speed-2-underground.html)
- [BLOXDHOP IO](https://themindplay.github.io/bloxdhop-io.html)
- [ARCHERS RAGDOLL PHYSICS](https://theskillquest.pages.dev/archers-ragdoll-physics.html)
- [PLANT GIRL DEFENSE ZOMBIE](https://thelearnquesters.pages.dev/plant-girl-defense-zombie.html)
- [CLINIC CLEANUP CREW](https://themindplay.pages.dev/clinic-cleanup-crew.html)
- [CATEGORY SURVIVAL366](https://thelearnquesters.pages.dev/category-survival366.html)
- [BLACK PINK CHRISTMAS CONCERT](https://themindplay.pages.dev/black-pink-christmas-concert.html)
- [CIRCLE SHOOTER MASTER](https://thequizzone.pages.dev/circle-shooter-master.html)
- [MICROPLASTICS FEEDING](https://theskillquest.pages.dev/microplastics-feeding.html)
- [MEGA MAKEUP SEASONS BEST](https://thelearnquesters.pages.dev/mega-makeup-seasons-best.html)
- [EUROPE AT WAR](https://themindplay.github.io/europe-at-war.html)
- [PHOTO BLOCK JOURNEY](https://themindplay.pages.dev/photo-block-journey.html)
- [GEOMETRY TOWER DEFENSE](https://themindplay.pages.dev/geometry-tower-defense.html)
- [MY FARM](https://learnquesters.pages.dev/my-farm.html)
- [BRAINROT MERGE](https://themindplay.pages.dev/brainrot-merge.html)
- [CARS MERGE](https://learnquester.pages.dev/cars-merge.html)
- [ASCENT](https://themindplay.pages.dev/ascent.html)
- [COLOR IT IN 3D](https://learnquester.pages.dev/color-it-in-3d.html)
- [WORMSARENAIO](https://thequizzone.pages.dev/wormsarenaio.html)
- [CATEGORY PROXIES](https://learnquester.github.io/category-proxies.html)
- [CATEGORY COLLECT565](https://learnquester.github.io/category-collect565.html)
- [FAT CAT LIFE](https://thelearnquester.web.app/fat-cat-life.html)
- [DEAD BRAIN](https://studyplayings.web.app/dead-brain.html)
- [EVONY THE KINGS RETURN](https://studyplayings.web.app/evony-the-kings-return.html)
- [DRIVE TO SURVIVE](https://studyplayings.pages.dev/drive-to-survive.html)
- [CATEGORY 1 PLAYER139](https://themindplay.pages.dev/category-1-player139.html)
- [CATEGORY SNAKE](https://studyplayings.pages.dev/category-snake.html)
- [BUBBLE SHOOTER BILLIARDS POOL](https://studyplayings.pages.dev/bubble-shooter-billiards-pool.html)
- [BATTLE ISLAND 2](https://learnquester.github.io/battle-island-2.html)
- [DIAMOND MOSAIC](https://studyplayings.web.app/diamond-mosaic.html)
- [CATEGORY FPS 2](https://theskillquest.pages.dev/category-fps-2.html)
- [HILL RACING EGG DROP](https://themindplay.pages.dev/hill-racing-egg-drop.html)
- [CATEGORY QUIZ](https://learnquester.github.io/category-quiz.html)
- [SPACE SHIFT](https://learnquesters.pages.dev/space-shift.html)
- [SOCCER DASH](https://themindplay.pages.dev/soccer-dash.html)
- [GT MICRO RACERS](https://themindplay.pages.dev/gt-micro-racers.html)
- [CATEGORY SIMULATION 3](https://learnquester.pages.dev/category-simulation-3.html)
