FROM debian:bookworm

EXPOSE 80

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apache2 \
        libapache2-mod-php \
        && rm -rf /var/lib/apt/lists/*

COPY index.php /var/www/html/
COPY flag.txt /flag

RUN a2enmod php* && a2enmod rewrite
RUN rm /var/www/html/index.html
RUN chmod 644 /var/www/html/index.php /flag

WORKDIR /var/www/html

CMD ["apachectl", "-D", "FOREGROUND"]