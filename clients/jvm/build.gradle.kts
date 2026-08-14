// kivi JVM SDK (PLAN3 G3.3): Kotlin coroutines (the JVM's async idiom) with a
// Java-friendly blocking facade. Codegen happens at build time from the single
// contract ../../api/kivi.proto — nothing hand-written follows the wire format.
import com.google.protobuf.gradle.id
import com.vanniktech.maven.publish.SonatypeHost

plugins {
    kotlin("jvm") version "2.0.21"
    id("com.google.protobuf") version "0.9.4"
    id("com.vanniktech.maven.publish") version "0.30.0"
    application
}

group = "com.iwasoft"
version = "1.2.0"

repositories { mavenCentral() }

val grpcVersion = "1.68.1"
val grpcKotlinVersion = "1.4.1"
val protobufVersion = "3.25.5"

dependencies {
    implementation("io.grpc:grpc-netty-shaded:$grpcVersion")
    implementation("io.grpc:grpc-protobuf:$grpcVersion")
    implementation("io.grpc:grpc-stub:$grpcVersion")
    implementation("io.grpc:grpc-kotlin-stub:$grpcKotlinVersion")
    implementation("com.google.protobuf:protobuf-java:$protobufVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    compileOnly("org.apache.tomcat:annotations-api:6.0.53") // javax.annotation for grpc-java gen
}

kotlin { jvmToolchain(21) }

sourceSets {
    main {
        proto { srcDir("../../api") }
    }
}

protobuf {
    protoc { artifact = "com.google.protobuf:protoc:$protobufVersion" }
    plugins {
        id("grpc") { artifact = "io.grpc:protoc-gen-grpc-java:$grpcVersion" }
        id("grpckt") { artifact = "io.grpc:protoc-gen-grpc-kotlin:$grpcKotlinVersion:jdk8@jar" }
    }
    generateProtoTasks {
        all().forEach {
            it.plugins {
                id("grpc")
                id("grpckt")
            }
        }
    }
}

application { mainClass.set("kivi.conformance.MainKt") }

// Maven Central publishing (com.iwasoft:kivi). The vanniktech plugin builds the
// sources + javadoc jars Central requires, signs them, and uploads to the
// Central Portal. Credentials/GPG come from gradle properties or env at publish
// time — see clients/PUBLISHING.md. The server and core stay proprietary; this
// artifact is the MIT-licensed client SDK.
mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)
    signAllPublications()
    coordinates("com.iwasoft", "kivi", "1.1.0")
    pom {
        name.set("kivi")
        description.set("The untrusting client SDK for the kivi event-ledger database")
        url.set("https://iwasoft.com")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
            }
        }
        developers {
            developer { id.set("iwasoft"); name.set("iwasoft"); url.set("https://iwasoft.com") }
        }
        scm {
            url.set("https://github.com/iwasoftcom/kivi")
            connection.set("scm:git:https://github.com/iwasoftcom/kivi.git")
            developerConnection.set("scm:git:ssh://git@github.com/iwasoftcom/kivi.git")
        }
    }
}
