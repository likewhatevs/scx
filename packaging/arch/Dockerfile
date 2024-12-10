FROM archlinux
RUN pacman -Syu debugedit bpf meson rust llvm clang devtools nvchecker vim git make pkgconfig libbpf --noconfirm
ARG COMMIT
ENV COMMIT=$COMMIT
RUN git clone https://aur.archlinux.org/scx-scheds-git.git
WORKDIR /scx-scheds-git
RUN sed -i 's/prepare()\n\s*cd $_gitname/prepare()\n cd $_gitname\ngit checkout '$COMMIT\n'/g' PKGBUILD
RUN sed -i 's/exit $E_ROOT//g' /usr/bin/makepkg
RUN makepkg -s



