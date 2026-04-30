plugins {
    kotlin("jvm") version "2.0.21"
    java
    application
}

group = "com.redking"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // JGraphT for graph data structures
    implementation("org.jgrapht:jgrapht-core:1.5.2")

    // Kotlin coroutines for async networking
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // Logging
    implementation("org.slf4j:slf4j-api:2.0.9")
    implementation("ch.qos.logback:logback-classic:1.4.11")

    // Testing
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(21)
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

application {
    mainClass.set("redking.MainKt")
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "redking.MainKt"
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
}
