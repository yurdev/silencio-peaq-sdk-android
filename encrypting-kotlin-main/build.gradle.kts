import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
// this import for publishing
import com.vanniktech.maven.publish.SonatypeHost
import com.vanniktech.maven.publish.KotlinJvm

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    // this is for publishing
    id("com.vanniktech.maven.publish")
}



val dokkaVersion: String by project
val commonVersion: String by project
val hashingVersion: String by project
val sr25519Version: String by project
val eddsaVersion: String by project
val web3jCryptoVersion: String by project
val zcashBIP39Version: String by project

dependencies {
    testImplementation(kotlin("test"))
    dokkaHtmlPlugin("org.jetbrains.dokka:kotlin-as-java-plugin:$dokkaVersion")
    dokkaJavadocPlugin("org.jetbrains.dokka:kotlin-as-java-plugin:$dokkaVersion")
    implementation("dev.sublab:common-kotlin:$commonVersion")
    implementation("dev.sublab:hashing-kotlin:$hashingVersion")
    implementation("dev.sublab:sr25519-kotlin:$sr25519Version")
    implementation("net.i2p.crypto:eddsa:$eddsaVersion")
    implementation("org.web3j:crypto:$web3jCryptoVersion")
    implementation("cash.z.ecc.android:kotlin-bip39:$zcashBIP39Version")
}

tasks.test {
    useJUnitPlatform()
}

tasks.dokkaHtml.configure {
    outputDirectory.set(projectDir.resolve("reference"))
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "17"
}

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    dependsOn("dokkaJavadoc")
    from("$buildDir/dokka/javadoc")
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}


mavenPublishing {
    configure(KotlinJvm(
        // configures the -javadoc artifact, possible values:
        // - `JavadocJar.None()` don't publish this artifact
        // - `JavadocJar.Empty()` publish an emprt jar
        // - `JavadocJar.Dokka("dokkaHtml")` when using Kotlin with Dokka, where `dokkaHtml` is the name of the Dokka task that should be used as input
//        javadocJar = JavadocJar.Dokka("dokkaHtml"),
        // whether to publish a sources jar
        sourcesJar = true,
    ))
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL,true)


    signAllPublications()

    coordinates("store.silencio", "encrypting-kotlin-main", "1.0.8")

    pom {


        name = "Silencio encrypting-kotlin-main"
        description = ""
        inceptionYear = "2024"
        url = "https://github.com/SilencioNetwork/SilencioPeaq.Android/"
        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "http://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "http://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }
        developers {
            developer {
                id = "SilencioNetwork"
                name = "SilencioNetwork"
                url = "https://github.com/SilencioNetwork"
            }
        }
        scm {
            url = "https://github.com/SilencioNetwork/SilencioPeaq.Android/"
            connection = "scm:git:git://github.com/SilencioNetwork/SilencioPeaq.Android.git"
            developerConnection = "scm:git:ssh://git@github.com:SilencioNetwork/SilencioPeaq.Android.git"
        }

    }
}
