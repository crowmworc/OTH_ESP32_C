idf_component_register(SRCS "esp32_c3_main.c"
                       PRIV_REQUIRES spi_flash at_modem nvs_flash nvs_sec_provider
                       INCLUDE_DIRS "")
