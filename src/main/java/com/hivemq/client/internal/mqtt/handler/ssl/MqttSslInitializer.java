/*
 * Copyright 2018-present HiveMQ and the HiveMQ Community
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hivemq.client.internal.mqtt.handler.ssl;

import com.hivemq.client.internal.mqtt.MqttClientConfig;
import com.hivemq.client.internal.mqtt.MqttClientSslConfigImpl;
import com.hivemq.client.internal.util.collections.ImmutableList;
import io.netty.channel.Channel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import java.net.InetSocketAddress;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * @author Christoph Schäbel
 * @author Silvio Giebl
 */
public final class MqttSslInitializer {

    private static final @NotNull String SSL_HANDLER_NAME = "ssl";
    private static final @NotNull String ENDPOINT_IDENTIFICATION_ALGORITHM = "HTTPS";

    public static void initChannel(
            final @NotNull Channel channel,
            final @NotNull MqttClientConfig clientConfig,
            final @NotNull MqttClientSslConfigImpl sslConfig,
            final @NotNull Consumer<Channel> onSuccess,
            final @NotNull BiConsumer<Channel, Throwable> onError) {

        final InetSocketAddress serverAddress = clientConfig.getCurrentTransportConfig().getServerAddress();

        final SslHandler sslHandler;
        try {
            SslContext sslContext = clientConfig.getCurrentSslContext();
            if (sslContext == null) {
                sslContext = createSslContext(sslConfig);
                clientConfig.setCurrentSslContext(sslContext);
            }
            sslHandler = sslContext.newHandler(channel.alloc(), serverAddress.getHostString(), serverAddress.getPort());
        } catch (final Throwable t) {
            onError.accept(channel, t);
            return;
        }

        sslHandler.setHandshakeTimeoutMillis(sslConfig.getHandshakeTimeoutMs());

        /*
        SSLParameters.setEndpointIdentificationAlgorithm is called by netty because we called SslContextBuilder.endpointIdentificationAlgorithm.
        In Netty 4.1, this call is guarded by a Java version >= 7 check.
        Netty treats Android (all versions) as Java 6, so SSLParameters.setEndpointIdentificationAlgorithm is not called on Android with netty 4.1.
        So SSLParameters.setEndpointIdentificationAlgorithm still needs to be called here.
         */
        HostnameVerifier hostnameVerifier = sslConfig.getRawHostnameVerifier();
        if (hostnameVerifier == null) {
            final SSLParameters sslParameters = sslHandler.engine().getSSLParameters();
            try {
                sslParameters.setEndpointIdentificationAlgorithm(ENDPOINT_IDENTIFICATION_ALGORITHM);
                sslHandler.engine().setSSLParameters(sslParameters);
                if (!ENDPOINT_IDENTIFICATION_ALGORITHM.equals(
                        sslHandler.engine().getSSLParameters().getEndpointIdentificationAlgorithm())) {
                    /*
                    On Android API 24 and 25 SSLParameters.setEndpointIdentificationAlgorithm is available but the call is ignored
                    The HttpsURLConnection.getDefaultHostnameVerifier performs HTTPS hostname verification on Android
                     */
                    hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
                }
            } catch (final NoSuchMethodError e) {
                /*
                On Android API < 24 SSLParameters.setEndpointIdentificationAlgorithm is not available
                The HttpsURLConnection.getDefaultHostnameVerifier performs HTTPS hostname verification on Android
                 */
                hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
            }
        }

        final MqttSslAdapterHandler sslAdapterHandler =
                new MqttSslAdapterHandler(sslHandler, serverAddress.getHostString(), hostnameVerifier, onSuccess,
                        onError);

        channel.pipeline().addLast(SSL_HANDLER_NAME, sslHandler).addLast(MqttSslAdapterHandler.NAME, sslAdapterHandler);
    }

    static @NotNull SslContext createSslContext(final @NotNull MqttClientSslConfigImpl sslConfig) throws SSLException {
        final ImmutableList<String> protocols = sslConfig.getRawProtocols();

        return SslContextBuilder.forClient()
                .trustManager(sslConfig.getRawTrustManagerFactory())
                .keyManager(sslConfig.getRawKeyManagerFactory())
                .protocols((protocols == null) ? null : protocols.toArray(new String[0]))
                .ciphers(sslConfig.getRawCipherSuites(), SupportedCipherSuiteFilter.INSTANCE)
                .endpointIdentificationAlgorithm(
                        (sslConfig.getRawHostnameVerifier() == null) ? ENDPOINT_IDENTIFICATION_ALGORITHM : null)
                .build();
    }

    private MqttSslInitializer() {}
}
