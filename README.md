# Ghidra Kotlin-Script Provider

This Ghidra extension allows running ghidra-scripts written in Kotlin.

## Requirements

The extension uses `kotlinc` to compile Kotlin scripts. 
To install it, follow the instructions [here][install-kotlinc].
When finished, make sure that `kotlinc` is in your `PATH`.

## Installation


### The Proper Way

1. Download the [latest build][latest-release] for your version of Ghidra
2. In the main Ghidra window, go to `File -> Install Extensions` to open the extensions window
3. Once there, press the green `+` sign to install a new extension
4. Choose the zip archive you downloaded
5. Restart Ghidra

### Quick and Dirty

1. Download the [latest build][latest-release] for your version of Ghidra
2. Unpack it into `$GHIDRA_HOME/Ghidra/Extensions`
3. Launch Ghidra


## Usage

Once installed, you can use `.kt` scripts just like `.java` and `.py` scripts.

### Examples

Under `ghidra_scripts` you can find some example scripts.
The scripts are (mostly automatically) translated from Java scripts provided with Ghidra.
Once you install the extension, they should be available in the Script Manager.

### Writing Scripts in IntelliJ IDEA

To develop Kotlin in IntelliJ IDEA, with full auto-completion for the Ghidra APIs, there are
a few simple steps you need to perform:

1. Create a new Kotlin project in IntelliJ (see [this tutorial][create kotlin project])
2. Build the `ghidra.jar`. This only needs to be done once.
    ```bash
    $GHIDRA_HOME/support/buildGhidraJar
    ```
3. Define the generated `$GHIDRA_HOME/support/ghidra.jar` as a global library in IntelliJ
    (see [defining global libraries][define-global-library]). This only needs to be done once.
    This only needs to be done once, and will allow you to use it easily in the future.
4. Add the library from the previous step to your module dependencies (see 
    [adding libraries to module dependencies][add-module-deps]).
5. To load the scripts into Ghidra, add the `src` directory of your project to the
    Script Directories in Ghidra's Script Manager. 
6. For easy script creation, add the following template to your [IntelliJ file templates][file-template]:
    ```kotlin
    import ghidra.app.script.GhidraScript
    
    class ${NAME} : GhidraScript() {
        override fun run() {
            TODO("Write your code here.")
        }
    }
    ``` 

### Known Issues

#### 1. Avoid Kotlin scripts with names identical to Java scripts

If you have `MyScript.java` and `MyScript.kt`, and you run one of them, its code will be
used for both.

This happens because both will be compiled to `MyScript.class`. Once the first one is built,
Ghidra will find a `.class` file with a matching name and just use that. 

This is why all the example scripts have `Kt` appended to the names.

## Building the Extension

Gradle is required for building the extension.  Please see the
`application.gradle.version` property in `<GHIDRA_INSTALL_DIR>/Ghidra/application.properties`
for the correction version of Gradle to use for the Ghidra installation you specify.
Follow the instructions [here][install-gradle] to install the correct version of Gradle.

If you plan to use the "proper" install method, ensure the version in your `extension.properties`
matches your Ghidra version.

To build, open a terminal in the project directory and run the following:

```bash
export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra> 
gradle
```

If everything succeeds, you should see `BUILD SUCCESSFUL` written to the screen.
If the build fails with `error: cannot access ghidra.app.script`, just give it another
go and it should work.
Once done, a zip archive with the extension will be created under the `dist` directory.


[install-kotlinc]: https://kotlinlang.org/docs/tutorials/command-line.html
[latest-release]: https://github.com/VDOO-Connected-Trust/KotlinScriptProvider/releases/latest
[install-gradle]: https://gradle.org/install/
[create kotlin project]: https://kotlinlang.org/docs/tutorials/getting-started.html
[define-global-library]: https://www.jetbrains.com/help/idea/library.html#define-global-library
[add-module-deps]: https://www.jetbrains.com/help/idea/library.html#add-library-to-module-dependencies
[file-template]: https://www.jetbrains.com/help/idea/using-file-and-code-templates.html#create-new-template