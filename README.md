# CTF Wiki

[![Build Status](https://travis-ci.org/ctf-wiki/ctf-wiki.svg?branch=master)](https://travis-ci.org/ctf-wiki/ctf-wiki)
[![Requirements Status](https://requires.io/github/ctf-wiki/ctf-wiki/requirements.svg?branch=master)](https://requires.io/github/ctf-wiki/ctf-wiki/requirements/?branch=master)
[![Slack](https://img.shields.io/badge/slack-join%20chat-brightgreen.svg)](https://join.slack.com/t/ctf-wiki/shared_invite/enQtNTkwNDg5NDUzNzAzLWExOTRhZTE0ZTMzYjVlNDk5OGI3ZDA1NmQyZjE4NWRlMGU3NjEwM2Y2ZTliMTg4Njg1MjliNWRhNTk2ZmY0NmI)

[中文](./README-zh_CN.md)  [English](./README.md)

Welcome to **CTF Wiki**！

**CTF** (Capture The Flag) started from **DEFCON CTF**, a competitive game among network security enthusiasts, originally hosted in 1996.

**CTF** covers a wide range of fields. While the security technology is evolving faster and faster, the difficulty of **CTF** challenges is getting increasingly harder. As a result, the learning curve for beginners is getting steeper. Most online information is scattered and trivial. Beginners often don't know how to systematically learn **CTF** related knowledge. Requiring a lot of work and effort.

In order to get those who have a interest in **CTF**s to get started, in October 2016, **CTF Wiki** had its first commit on Github. While the content gradually improves over time, **CTF Wiki** has received a lots of appreciation from security enthusiasts, many of those whom we never thought we would meet.

As a open source site, primarily focusing on recent CTFs, **CTF Wiki** introduces the knowledge and techniques from all aspects of **CTF** to make it easier for beginners to learn **CTF**.

As of now, **CTF Wiki** mainly contains the basic skill-set for a **CTF**, and we are working hard to improve on the following contents.

- Advanced skills used in CTF
- Special topics appearing in CTF

For the above-mentioned parts to be improved, please refer to [Projects](https://github.com/ctf-wiki/ctf-wiki/projects) which details what has been done and what others are planned.

Although **CTF Wiki** mainly revolves around **CTF**, it is not strictly limited to **CTF** topics. In the future, **CTF Wiki** will include

- Tools used in security research
- Increased discussion of security in the world

In addition, given the following two points

- Information about technology should be openly shared.
- As new techniques are always being developed, old techniques will start to fade over time and new techniques will have to replace them.

Therefore, **CTF Wiki** will never publish books.

Finally, originating from the community, as an independent organization, **CTF Wiki** advocates **freedom of knowledge**, will **never be commercialized**, and will always maintain the character of **independence and freedom**.

## How to build？

CTF Wiki uses [mkdocs](https://github.com/mkdocs/mkdocs) to show its contents. And it is deployed at [https://ctf-wiki.github.io/ctf-wiki/](https://ctf-wiki.github.io/ctf-wiki/).

It can also be deployed locally, with the following steps:

```shell
# 1. clone
git clone https://github.com/ctf-wiki/ctf-wiki.git
# 2. requirements
pip install -r requirements.txt
# generate static file in site/
mkdocs build
# deploy at http://127.0.0.1:8000
mkdocs serve
```

** A local instance of mkdocs is dynamically updated, for instance when a markdown file is modified, the corresponding page will be too **

If you just want to view it statically, try Docker!

```
docker run -d --name=ctf-wiki -p 4100:80 ctfwiki/ctf-wiki
```
And then access [http://localhost:4100/](http://localhost:4100/) .

## How to practice？

Firstly, learn some basic security knowledge through online reading.

Secondly, CTF Wiki has two sister projects.

- All of the challenges that are mentioned in the pages are in the [ctf-challenges](https://github.com/ctf-wiki/ctf-challenges) repository, you can locate them with their corresponding category.
  - Note: There are still some topics that are still being migrated. . . (misc, web)
- The tools mentioned in the CTF Wiki are constantly added to the [ctf-tools](https://github.com/ctf-wiki/ctf-tools) repository.

## How to make CTF Wiki Better？

We welcome to write content for the wiki and share what you have learned. 

**Before you decide to contribute content, please be sure to read [CONTRIBUTING](https://github.com/ctf-wiki/ctf-wiki/wiki/Contributing-Guide)**.

Thank you to all the people who have already contributed to CTF Wiki.

<a href="https://github.com/ctf-wiki/ctf-wiki/graphs/contributors"><img src="https://opencollective.com/ctf-wiki/contributors.svg?width=890&button=false" />

## What can you get?

- Ability to learn new things quickly
- Different ways of thinking
- A love for solving problems
- Interesting security techniques
- Memorable and enriching experience

Before reading the Wiki, we hope to give you some advice:

- Learn to ask [smart-questions](http://www.catb.org/~esr/faqs/smart-questions.html) .
- Making extensive use of Google Search for self-improvement.
- Be comfortable at least one programming language, such as Python.
- Practice is the most important learning tool.
- Maintain the passions and desire to learn about new techniques..

The security circle is small and the areas of exploration is vast. Let's get started with **CTF Wiki**!
