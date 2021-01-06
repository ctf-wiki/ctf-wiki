# Document Requirements

When you intend to contribute something, you should assure

- Content format
- Content structure
- File name and file path

meet the following requirements.

## Content format

!!! note 
    For the basic content format, it is needed to be discussed.

Some other requirements

- In the future, we may consider to automatically generate a sequence number for every paragraph title, so we recommend **no** sequence number for paragraph titles.
- As the challenges mentioned in the doc are placed in the `ctf-challenge` repository in order, we don't need to include a link to the challenge in the documentation. Moreover, every time the challenge's location in the repository changes, the challenge link also changes. Therefore, fixing the challenge link is a time-consuming and annoying task.

## Content structure

The content must have the following characteristics

- From easy to hard, the difficulty of content should be gradual.
- Logical, every part should contain the following items
  - Principle, explaining the principle corresponding to this content.
  - Examples, give 1 to 2 typical examples.
  - Exercises, give 1 to 2 typical exercises.

## File name and file path

Document should be stored in the appropriate directory.

- Figure. Please note that the image should be placed in a local folder. We should avoid referencing image from other websites. We recommend using a relative path `./figure` to reference the image.
- **File names must be lowercase, separated by `-`, e.g. `file-name`**.
- Regardless of the example or the exercise, the corresponding attachments should be stored in the corresponding directory in the `ctf-challenge` repository.