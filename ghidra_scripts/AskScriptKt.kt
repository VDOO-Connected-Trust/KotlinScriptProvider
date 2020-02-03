/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// An example of asking for user input.
// Note the ability to pre-populate values for some of these variables when AskScript.properties file exists.
// Also notice how the previous input is saved.
// @category Examples

import ghidra.app.script.GhidraScript
import ghidra.framework.model.DomainFile
import ghidra.framework.model.DomainFolder
import ghidra.program.model.address.Address
import ghidra.program.model.lang.LanguageCompilerSpecPair
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import java.io.File
import java.util.Arrays

class AskScriptKt : GhidraScript() {
    @Throws(Exception::class)
    override fun run() {
        // The presence of the AskScript.properties file in the same location (as AskScript.java)
        // allows for the following behavior:
        // 		- GUI: if applicable, auto-populates the input field with the value in the
        // 			.properties file (the first	time that input	field appears)
        //   	- Headless: uses the value in the .properties file for the variable assigned to the
        // 			corresponding askXxx() method in the GhidraScript.
        try {
            val file1: File = askFile("FILE", "Choose file:")
            println("file was: $file1")

            val directory1: File = askDirectory("Directory", "Choose directory:")
            println("directory was: $directory1")

            val lang: LanguageCompilerSpecPair = askLanguage("Language Picker", "I want this one!")
            println("language was: " + lang.toString())

            val domFolder: DomainFolder = askProjectFolder("Please pick a domain folder!")
            println("domFolder was: " + domFolder.getName())

            val int1: Int = askInt("integer 1", "enter integer 1")
            val int2: Int = askInt("integer 2", "enter integer 2")
            println("int1 + int2 = " + (int1 + int2))

            val long1: Long = askLong("long 1", "enter long 1")
            val long2: Long = askLong("long 2", "enter long 2")
            println("long1 + long2 = " + (long1 + long2))

            val address1: Address = askAddress("address 1", "enter address 1")
            val address2: Address = askAddress("address 2", "enter address 2")
            println("address1 + address2 = " + address1.add(address2.getOffset()).toString())

            val bytes: ByteArray = askBytes("bytes", "enter byte pattern")
            for (b in bytes) {
                println("b = $b")
            }

            val prog: Program = askProgram("Please choose a program to open.")
            println("Program picked: " + prog.getName())

            val domFile: DomainFile = askDomainFile("Which domain file would you like?")
            println("Domain file: " + domFile.getName())

            val d1: Double = askDouble("double 1", "enter double 1")
            val d2: Double = askDouble("double 2", "enter double 2")
            println("d1 + d2 = " + (d1 + d2))

            val myStr: String = askString("String Specification", "Please type a string: ")
            val myOtherStr: String = askString(
                    "Another String Specification",
                    "Please type another string: ", "replace me!"
            )
            println("You typed: $myStr and $myOtherStr")

            val choice: String = askChoice(
                    "Choice", "Please choose one",
                    Arrays.asList(*arrayOf("grumpy", "dopey", "sleepy", "doc", "bashful")),
                    "bashful"
            )
            println("Choice? $choice")

            val choices1: List<Int> = askChoices(
                    "Choices 1", "Please choose one or more numbers.",
                    Arrays.asList(1, 2, 3, 4, 5, 6)
            )
            print("Choices 1: ")

            for (intChoice in choices1) {
                print("$intChoice ")
            }
            println("")

            val choices2: List<Double> = askChoices(
                    "Choices 2", "Please choose one or more of the following.",
                    Arrays.asList(1.1, 2.2, 3.3, 4.4, 5.5, 6.6),
                    Arrays.asList("Part 1", "Part 2", "Part 3", "Part 4", "Part 5", "Part 6")
            )
            print("Choices 2: ")

            for (intChoice in choices2) {
                print("$intChoice ")
            }
            println("")

            val yesOrNo: Boolean = askYesNo("yes or no", "is this a yes/no question?")
            println("Yes or No? $yesOrNo")
        } catch (iae: IllegalArgumentException) {
            Msg.warn(this, "Error during headless processing: $iae")
        }
    }
}
