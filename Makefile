.PHONY: all build-jupyter build-tests build-final jupyter pause address containers \
        list-containers stop-containers restart-containers lint tests pytest \
        deptry isort black flake8 mypy nox shell clear-nb clean install-act \
        check-act run-act-tests test-py-version

# Usage:
# make                    # just alias to containers command
# make build-jupyter      # build jupyter docker image
# make build-tests        # build testing docker image
# make build-final        # build final docker image
# make jupyter            # startup Docker container running Jupyter server
# make pause              # pause PSECS (to pause between commands)
# make address            # get Docker container address/port
# make containers         # launch all Docker containers
# make list-containers    # list all running containers
# make stop-containers    # simply stops all running Docker containers
# make restart-containers # restart all containers
# make lint               # run linters
# make tests              # run full testing suite
# make pytest             # run pytest in docker container
# make deptry             # run deptry in docker container
# make isort              # run isort in docker container
# make black              # run black in docker container
# make flake8             # run flake8 in docker container
# make mypy               # run mypy in docker container
# make nox                # run nox sessions in docker container
# make shell              # create interactive shell in docker container
# make clear-nb           # simply clears Jupyter notebook output
# make clean              # combines all clearing commands into one
# make install-act        # install act command
# make check-act          # check if act is installed
# make run-cat-tests      # run github action tests locally
# make test-py-version    # print default python test version


################################################################################
# GLOBALS                                                                      #
################################################################################

# make cli args
DCTNR := $(notdir $(PWD))
INTDR := notebooks
PSECS := 5

# notebook-related variables
CURRENTDIR := $(PWD)
NOTEBOOKS  := $(shell find ${INTDR} -name "*.ipynb" -not -path "*/.ipynb_*/*")

# docker-related variables
JPTCTNR = jupyter.${DCTNR}
SRCPATH = /usr/local/src/secrepo
DCKR_PULL ?= true
DCKR_NOCACHE ?= false
DCKRTTY := $(if $(filter true,$(NOTTY)),-i,-it)
USE_VOL ?= true
USE_USR ?= true
USE_FNL ?= false
JPTRVOL = $(if $(filter true,$(USE_VOL)),-v ${CURRENTDIR}:/home/jovyan,)
TESTVOL = $(if $(filter true,$(USE_VOL)),-v ${CURRENTDIR}:${SRCPATH},)
DCKRUSR = $(if $(filter true,$(USE_USR)),--user $(shell id -u):$(shell id -g),)
DCKRRUN = docker run --rm ${JPTRVOL} ${DCKRTTY}
DCKRTST = docker run --rm ${DCKRUSR} ${TESTVOL} ${DCKRTTY}
DCKRIMG_BASE ?= ghcr.io/diogenesanalytics/secrepo:master
DCKRIMG_JPYTR ?= ${DCKRIMG_BASE}_jupyter
DCKRIMG_TESTS ?= ${DCKRIMG_BASE}_testing
DCKRIMG_FINAL ?= ${DCKRIMG_BASE}_final
TSTIMG_USED = $(if $(filter true,$(USE_FNL)),${DCKRIMG_FINAL},${DCKRIMG_TESTS})

# jupyter nbconvert vars
NBCLER = jupyter nbconvert --clear-output --inplace

# Define the docker build command with optional --no-cache
define DOCKER_BUILD
	docker build -t $1 . --load --target $2 \
	  $(if $(filter true,$(DCKR_NOCACHE)),--no-cache)
endef

# Function to conditionally pull or build the docker image
define DOCKER_PULL_OR_BUILD
	$(if $(filter true,$(DCKR_PULL)), \
	  docker pull $1 || (echo "Pull failed. Building Docker image for $1..." && \
	  $(call DOCKER_BUILD,$1,$2)), $(call DOCKER_BUILD,$1,$2))
endef

################################################################################
# COMMANDS                                                                     #
################################################################################

# launch jupyter
all: containers

# build jupyter docker image with conditional pull and build
build-jupyter:
	@ echo "Building Jupyter Docker image..."
	@ $(call DOCKER_PULL_OR_BUILD,${DCKRIMG_JPYTR},jupyter)

# build testing docker image with conditional pull and build
build-tests:
	@ echo "Building Test Docker image..."
	@ $(call DOCKER_PULL_OR_BUILD,${DCKRIMG_TESTS},testing)

# build-final target to build the final test image with the Nox setup
build-final:
	@ echo "Building Final Docker image..."
	@ $(call DOCKER_PULL_OR_BUILD,${DCKRIMG_FINAL},final)

# launch jupyter notebook development Docker image
jupyter:
	@ echo "Launching Jupyter in Docker container -> ${JPTCTNR} ..."
	@ if ! docker ps --format={{.Names}} | grep -q "${JPTCTNR}"; then \
	  docker run -d \
	             --rm \
	             --name ${JPTCTNR} \
	             -e JUPYTER_ENABLE_LAB=yes \
	             -p 8888 \
	             -v "${CURRENTDIR}":"${SRCPATH}" \
	             ${DCKROPT} \
	             ${DCKRIMG_JPYTR} && \
	  if ! grep -sq "${JPTCTNR}" "${CURRENTDIR}/.running_containers"; then \
	    echo "${JPTCTNR}" >> .running_containers; \
	  fi \
	else \
	  echo "Container already running. Try setting DCTNR manually."; \
	fi

# simply wait for a certain amount of time
pause:
	@ echo "Sleeping ${PSECS} seconds ..."
	@ sleep ${PSECS}

# get containerized server address
address:
	@ if [ -f "${CURRENTDIR}/.running_containers" ]; then \
	while read container; do \
	  if echo "$${container}" | grep -q "${JPTCTNR}" ; then \
	    echo "Server address: $$(docker logs $${container} 2>&1 | \
	          grep http://127.0.0.1 | tail -n 1 | \
	          sed s/:8888/:$$(docker port $${container} | \
	          grep '0.0.0.0:' | awk '{print $$3}' | sed 's/0.0.0.0://g')/g | \
	          tr -d '[:blank:]')"; \
	  else \
	    echo "Could not find running container: ${JPTCTNR}." \
	         "Try running: make list-containers"; \
	  fi \
	done < "${CURRENTDIR}/.running_containers"; \
	else \
	  echo ".running_containers file not found. Is a Docker container running?"; \
	fi

# launch all docker containers
containers: jupyter pause address

# list all running containers
list-containers:
	@ if [ -f "${CURRENTDIR}/.running_containers" ]; then \
	echo "Currently running containers:"; \
	while read container; do \
	  echo "-->  $${container}"; \
	done < "${CURRENTDIR}/.running_containers"; \
	else \
	  echo ".running_containers file not found. Is a Docker container running?"; \
	fi

# stop all containers
stop-containers:
	@ if [ -f "${CURRENTDIR}/.running_containers" ]; then \
	  echo "Stopping Docker containers ..."; \
	  while read container; do \
	    echo "Container $$(docker stop $$container) stopped."; \
	  done < "${CURRENTDIR}/.running_containers"; \
	  rm -f "${CURRENTDIR}/.running_containers"; \
	else \
	  echo "${CURRENTDIR}/.running_containers file not found."; \
	fi

# restart all containers
restart-containers: stop-containers containers

# run linters
lint: deptry isort black flake8 mypy

# run full testing suite
tests: pytest lint

# run pytest in docker container
pytest:
	@ echo "==> Running pytest..."
	@ ${DCKRTST} ${TSTIMG_USED} pytest

# run deptry in docker container
deptry:
	@ echo "==> Running deptry..."
	@ ${DCKRTST} ${TSTIMG_USED} deptry src/

# run isort in docker container
isort:
	@ echo "==> Running isort..."
	@ ${DCKRTST} ${TSTIMG_USED} isort .

# run black in docker container
black:
	@ echo "==> Running black..."
	@ ${DCKRTST} ${TSTIMG_USED} black .

# run flake8 in docker container
flake8:
	@ echo "==> Running flake8..."
	@ ${DCKRTST} ${TSTIMG_USED} flake8

# run mypy in docker container
mypy:
	@ echo "==> Running mypy..."
	@ ${DCKRTST} ${TSTIMG_USED} mypy .

# run nox sessions
nox:
	@ echo "==> Running nox..."
	@ ${DCKRTST} ${TSTIMG_USED} nox $(ARGS)

# create interactive shell in docker container
shell:
	@ ${DCKRTST} ${TSTIMG_USED} bash || true

# remove output from executed notebooks
clear-nb:
	@ echo "Removing all output from Jupyter notebooks."
	@ ${DCKRRUN} ${DCKRIMG_JPYTR} ${NBCLER} ${NOTEBOOKS}

# cleanup everything
clean: clear-nb

# install act command
install-act:
	@ echo "Installing act..."
	@ curl --proto '=https' --tlsv1.2 -sSf \
	  "https://raw.githubusercontent.com/nektos/act/master/install.sh" | \
	  sudo bash -s -- -b ./bin && \
	sudo mv ./bin/act /usr/local/bin/
	@ echo "act installed and moved to /usr/local/bin"

# check if act is installed
check-act:
	@ command -v act >/dev/null 2>&1 && \
	{ echo "✅ 'act' is installed!"; } || \
	{ echo "❌ Command 'act' is not installed. Please install it with: "\
	"'make install-act' 💻🔧"; exit 1; }

# run github action tests locally
run-act-tests: check-act
	@ echo "Running GitHub Action Tests locally..."
	act -j run-tests $(ARGS)

# get default python version
test-py-version:
	@ ${DCKRTST} ${TSTIMG_USED} python --version
