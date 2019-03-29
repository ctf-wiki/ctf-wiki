# CTF Wiki

[![Build Status](https://travis-ci.org/ctf-wiki/ctf-wiki.svg?branch=master)](https://travis-ci.org/ctf-wiki/ctf-wiki)
[![Requirements Status](https://requires.io/github/ctf-wiki/ctf-wiki/requirements.svg?branch=master)](https://requires.io/github/ctf-wiki/ctf-wiki/requirements/?branch=master)
[![Slack](https://img.shields.io/badge/slack-join%20chat-brightgreen.svg)](https://join.slack.com/t/ctf-wiki/shared_invite/enQtNTkwNDg5NDUzNzAzLWExOTRhZTE0ZTMzYjVlNDk5OGI3ZDA1NmQyZjE4NWRlMGU3NjEwM2Y2ZTliMTg4Njg1MjliNWRhNTk2ZmY0NmI)

[中文](./README-zh_CN.md)  [English](./README.md)

Welcome to **CTF Wiki**！

**CTF** (Capture The Flag) started from **DEFCON CTF**, a competitive game among network security enthusiasts, originally hosted in 1996.

**CTF** covers a wide range of fields. While, the security technology is evolving faster and faster, the difficulty of **CTF** is getting progressively harder. As a result, the threshold for beginners is getting progressively higher. Most of the online information is scattered and trivial. Beginners often don't know how to systematically learn **CTF** related domain knowledge. Also, it takes a lot of time.

In order to make the people who love **CTF** get started **CTF**ing, in October 2016, **CTF Wiki** was launched on Github. With rich content, **CTF Wiki** receives a lots of appreciation from security enthusiasts, many friends whom we never thought we'ed meet.

As a freedom site, focusing on recent year's CTF, **CTF Wiki** introduces the knowledge and techniques from all directions of **CTF** to make it easier for beginners to learn **CTF**.

Now, **CTF Wiki** mainly contains the basic knowledge of **CTF**, and we are now working hard to enrich the following contents.

- Advanced knowledge about CTF
- High quality topics about CTF

For the above-mentioned parts to be improved, please refer to the [Projects](https://github.com/ctf-wiki/ctf-wiki/projects) which details what to do.

While **CTF Wiki** is now based on **CTF**, it is not limited to **CTF**. In future, **CTF Wiki** will

- Introducing tools in security research
- More integration with security

In addition, given the following two points

- Technology should be shared in an open manner.
- Security offensive and defensive technologies are always up to date. Old attack technologies may fail at any time in the face of new defense technologies.

Therefore, **CTF Wiki** will never publish books.

Finally, originating from the community, as an independent organization, **CTF Wiki** advocates **freedom of knowledge**, will **never be commercialized** in the future, and will always maintain the nature of **independence and freedom**.

## How to build？

Now, CTF Wiki uses [mkdocs](https://github.com/mkdocs/mkdocs) to show its contents. And it is deployed at [https://ctf-wiki.github.io/ctf-wiki/](https://ctf-wiki.github.io/ctf-wiki/).

Of course, it can be deployed locally, do as following

```shell
# 1. clone
git clone git@github.com:ctf-wiki/ctf-wiki.git
# 2. requirements
pip install -r requirements.txt
# generate static file in site/
mkdocs build
# deploy at http://127.0.0.1:8000
mkdocs serve
```

The locally deployed mkdocs website is dynamically updated, i.e. when you modify and save the markdown file, the page will be dynamically updated.

If you just want to view it without any modify, try Docker!

```
docker run -d --name=ctf-wiki -p 4100:80 ctfwiki/ctf-wiki
```
And then access [http://localhost:4100/](http://localhost:4100/) .

## How to practice？

First, learn some basic security knowledge through online reading.

Second, CTF Wiki has two sister projects.

- All of the challenges talked in the readings are in the [ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) repository, you can look for them according to the corresponding category. Note: There are still some topics under the warehouse that are currently being migrated. . . (misc, web)
- The tools involved in the CTF Wiki are constantly added to the [ctf-tools](https://github.com/ctf-wiki/ctf-tools) repository.

## How to make CTF Wiki Better？

Welcome to write content for the wiki and share what you have learned. 

**Before you decide to contribute content, please be sure to read [CONTRIBUTING](https://github.com/ctf-wiki/ctf-wiki/wiki/Contributing-Guide)**.

Thank you to all the people who have already contributed to CTF Wiki.

<a href="https://github.com/ctf-wiki/ctf-wiki/graphs/contributors"><img src="https://opencollective.com/ctf-wiki/contributors.svg?width=890&button=false" />

## What can you get?

- Ability to learn new things quickly
- Different ways of thinking
- A willing heart to solve problems
- Interesting security technology
- Memorable time

Before reading the Wiki, we hope to give you some advice:

- Learn [smart-questions](http://www.catb.org/~esr/faqs/smart-questions.html) .
- Making good use of Google Search can help you better improve yourself.
- Master at least one programming language, such as Python.
- Practice is more useful than anything.
- Keep curiosity and desire for technology and stick to it.

The security circle is small and the security ocean is deep. Let's get started from **CTF Wiki**!
