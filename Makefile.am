SUBDIRS= src doc #utils

%-tarfile: all
	@rm -rf tmp
	@mkdir -p tmp
	@make -C doc/latex/
	@cp src/Makefile.djgpp \
		src/ds3ccfns2.cc \
		src/ds3ccfns2.h \
		src/ds3pktccf.cc \
		src/ds3pktccf.h \
		src/ds3pktcnt.cc \
		src/ds3pktcnt.h \
		src/testccf.cc \
		src/testccf.h \
		src/testmac.cc \
		src/testmac.h \
		doc/latex/refman.pdf \
		tmp/
	@sed -i -e 's|main1(void)|main(void)|' tmp/testccf.cc
	@make -C doc/latex/
	@cd tmp && rm -f ds3pktccf-*.tar.gz && tar -cvzf ds3pktccf-$*-`date +%Y%m%d`.tar.gz *