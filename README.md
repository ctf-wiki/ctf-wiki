# CTF Wiki

[![Build Status](https://travis-ci.org/ctf-wiki/ctf-wiki.svg?branch=master)](https://travis-ci.org/ctf-wiki/ctf-wiki)
[![Requirements Status](https://requires.io/github/ctf-wiki/ctf-wiki/requirements.svg?branch=master)](https://requires.io/github/ctf-wiki/ctf-wiki/requirements/?branch=master)
[![Slack](https://img.shields.io/badge/slack-join%20chat-brightgreen.svg)](https://join.slack.com/t/ctf-wiki/shared_invite/enQtNTkwNDg5NDUzNzAzLTQ3YTliNzI5OGNhM2NmNzI3NTU0YWRlNWFkY2EzYTExN2Y3ZjRkNzYzYmRhNDNlYmY5YTVmNjNhYjliZDgyNTY)

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

<a href="https://github.com/ctf-wiki/ctf-wiki/graphs/contributors"><img src="https://opencollective.com/ctf-wiki/contributors.svg?width=890&button=false" /></a>

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
