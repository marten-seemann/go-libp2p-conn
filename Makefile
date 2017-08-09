gx:
	go get github.com/whyrusleeping/gx
	go get github.com/whyrusleeping/gx-go

covertools:
	go get github.com/mattn/goveralls
	go get golang.org/x/tools/cmd/cover

ginkgo:
	go get github.com/onsi/ginkgo/ginkgo
	go get github.com/onsi/gomega

deps: gx covertools ginkgo
	gx --verbose install --global
	gx-go rewrite

publish:
	gx-go rewrite --undo

