plugins {
    application
    id("java")
}

group = "me.wega"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}


application {
    mainClass = "me.wega.Main"
}

tasks.test {
    useJUnitPlatform()
}