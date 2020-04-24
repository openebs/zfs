
# Development Workflow

## Prerequisites
* Since CStor works with Linux only, you need to have a working Linux machine
* Make sure that GCC, with version >6 is installed in your system.
  To install GCC, run
  ```sh
  sudo apt-get install --yes -qq gcc-6 g++-6
  ```
* Make sure that you have installed following packages in your system:
    - build-essential, autoconf, libtool, gawk, alien, fakeroot, libaio-devbuild, libjemalloc-dev
    - zlib1g-dev, uuid-dev, libattr1-dev, libblkid-dev, libselinux-dev, libudev-dev, libssl-dev, libjson-c-dev
    - libgtest-dev, cmake
  To install the above packages, run
  ```sh
  sudo apt-get install --yes -qq build-essential autoconf libtool gawk alien fakeroot libaio-dev libjemalloc-dev
  sudo apt-get install --yes -qq zlib1g-dev uuid-dev libattr1-dev libblkid-dev libselinux-dev libudev-dev libssl-dev libjson-c-dev
  sudo apt-get install --yes -qq libgtest-dev cmake
  ```
  For gtest, you need to run following command after installing the package
  ```sh
  cd /usr/src/gtest
  sudo cmake CMakeLists.txt
  sudo make -j4
  sudo cp *.a /usr/lib
  ```
* Make sure that you have installed libcstor in the system. Refer [installing libcstor](https://github.com/openebs/libcstor/blob/master/developer-setup.md)

* Make sure that you have cloned and build fio(branch fio-3.7) code in the linux system.
  Please use below command for the fio
  ``sh
  git clone https://github.com/axboe/fio
  cd fio
  git checkout fio-3.7
  ./configure
  make -j4
  ```

## Initial Setup

### Fork in the cloud

1. Visit https://github.com/openebs/cstor
2. Click the `Fork` button (top right) to establish a cloud-based fork.

### Clone fork to the local machine

Create your clone:

```sh
# Note: Here user= your github profile name
git clone https://github.com/$user/cstor.git

# Configure remote upstream
cd cstor
git remote add upstream https://github.com/openebs/cstor.git

# Never push to upstream develop
git remote set-url --push upstream no_push

# Confirm that your remotes make sense:
git remote -v
```

### Building and Testing your changes

* To build the cstor binary
```sh
sh autogen.sh
./configure --with-config=user --enable-debug --enable-uzfs=yes --with-jemalloc --with-fio=$PWD/../fio
make
```

* To build the docker image
```sh
./build_images.sh
```

* Test your changes
Integration tests are written in c and c+. Test script is maintained at https://github.com/openebs/libcstor/blob/master/tests/cstor/script/test_uzfs.sh
To run the run the integration tests.
```sh
../libcstor/tests/cstor/script/test_uzfs.sh -T all
```

## Git Development Workflow

### Always sync your local repository:
Open a terminal on your local machine. Change directory to the cstor fork root.

```sh
$ cd cstor
```

 Check out the develop branch.

 ```sh
 $ git checkout develop
 Switched to branch 'develop'
 Your branch is up-to-date with 'origin/develop'.
 ```

 Recall that origin/develop is a branch on your remote GitHub repository.
 Make sure you have the upstream remote openebs/cstor by listing them.

 ```sh
 $ git remote -v
 origin	https://github.com/$user/cstor.git (fetch)
 origin	https://github.com/$user/cstor.git (push)
 upstream	https://github.com/openebs/cstor.git (fetch)
 upstream	https://github.com/openebs/cstor.git (no_push)
 ```

 If the upstream is missing, add it by using the below command.

 ```sh
 $ git remote add upstream https://github.com/openebs/cstor.git
 ```
 Fetch all the changes from the upstream develop branch.

 ```sh
 $ git fetch upstream develop
 remote: Counting objects: 141, done.
 remote: Compressing objects: 100% (29/29), done.
 remote: Total 141 (delta 52), reused 46 (delta 46), pack-reused 66
 Receiving objects: 100% (141/141), 112.43 KiB | 0 bytes/s, done.
 Resolving deltas: 100% (79/79), done.
 From github.com:openebs/cstor
   * branch            develop     -> FETCH_HEAD
 ```

 Rebase your local develop with the upstream/develop.

 ```sh
 $ git rebase upstream/develop
 First, rewinding head to replay your work on top of it...
 Fast-forwarded develop to upstream/develop.
 ```
 This command applies all the commits from the upstream develop to your local develop.

 Check the status of your local branch.

 ```sh
 $ git status
 On branch develop
 Your branch is ahead of 'origin/develop' by 12 commits.
 (use "git push" to publish your local commits)
 nothing to commit, working directory clean
 ```
 Your local repository now has all the changes from the upstream remote. You need to push the changes to your remote fork which is origin develop.

 Push the rebased develop to origin develop.

 ```sh
 $ git push origin develop
 Username for 'https://github.com': $user
 Password for 'https://$user@github.com':
 Counting objects: 223, done.
 Compressing objects: 100% (38/38), done.
 Writing objects: 100% (69/69), 8.76 KiB | 0 bytes/s, done.
 Total 69 (delta 53), reused 47 (delta 31)
 To https://github.com/$user/cstor.git
 8e107a9..5035fa1  develop -> develop
 ```

### Contributing to a feature or bugfix.

Always start with creating a new branch from develop to work on a new feature or bugfix. Your branch name should have the format XX-descriptive where XX is the issue number you are working on followed by some descriptive text. For example:

 ```sh
 $ git checkout develop
 # Make sure the develop is rebased with the latest changes as described in the previous step.
 $ git checkout -b 1234-fix-developer-docs
 Switched to a new branch '1234-fix-developer-docs'
 ```
Happy Hacking!

### Keep your branch in sync

[Rebasing](https://git-scm.com/docs/git-rebase) is very important to keep your branch in sync with the changes being made by others and to avoid huge merge conflicts while raising your Pull Requests. You will always have to rebase before raising the PR.

```sh
# While on your myfeature branch (see above)
git fetch upstream
git rebase upstream/develop
```

While you rebase your changes, you must resolve any conflicts that might arise and build and test your changes using the above steps.

## Submission

### Create a pull request

Before you raise the Pull Requests, ensure you have reviewed the checklist in the [CONTRIBUTING GUIDE](CONTRIBUTING.md):
- Ensure that you have re-based your changes with the upstream using the steps above.
- Ensure that you have added the required unit tests for the bug fix or a new feature that you have introduced.
- Ensure your commit history is clean with proper header and descriptions.

Go to the [openebs/cstor github](https://github.com/openebs/cstor) and follow the Open Pull Request link to raise your PR from your development branch.

