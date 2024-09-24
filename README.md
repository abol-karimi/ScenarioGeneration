# ScenarioGeneration

I haven't had the chance to write a real README file, but here are some clues:

* The latest container is based on Apptainer. The main one is `Apptainer/definitions/scenariogen-bionic.apptainer` and you can trace back the dependencies in the denition files to infer the order needed to build the images.
* See the experiment script `evaluation/experiments/RQ1/trials_slurm.py` for an example of using the project.
