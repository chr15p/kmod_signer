package main

import (
	//"context"
	"errors"
	"fmt"
	"net/http"
	"archive/tar"
	"io"
	"os"
	"strings"
	"os/exec"
	"path/filepath"
	"bytes"
	"flag"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/types"
)


func getenv(key string, fallback string) string{
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	fmt.Printf("%s=%s\n", key, value)
	return value
}

func checkarg(arg *string, envvar string, fallback string) {
	if *arg == "" {
		if envvar != "" {
			v, exists := os.LookupEnv(envvar)
			if exists {
				*arg = v
			}else if !exists && fallback != "" {
				*arg = fallback
			} else {
				fmt.Printf("%s not found:\n", envvar)
				flag.PrintDefaults()
				os.Exit(0)
			}
		}
	}
	return
}



func canonicalisePath(path string) string {
	canonical := strings.Replace("/" + path, "/./","/", -1)
	return strings.Replace(canonical, "//","/", -1)
}


func extractFile(tmpdir string, header *tar.Header, tarreader io.Reader) string{

	contents := make([]byte, header.Size)
	offset := 0
	for {
		rc, err := tarreader.Read(contents[offset:])
		if err != nil && err != io.EOF {
			fmt.Errorf("could not read ko file: %v", err)
			panic("file")
		}
		offset += rc
		if err == io.EOF {
			break
		}
	}
	dirname := filepath.Dir(header.Name)
	err := os.MkdirAll(tmpdir +"/"+ dirname, 0750)
	if err != nil {
		fmt.Errorf("could not create tempdir for kmod: %v", err)
		panic(err)
	}
	err = os.WriteFile(tmpdir +"/"+ header.Name, contents, 0700 )
	if err != nil {
		fmt.Errorf("could not create temp kmod: %v", err)
		panic(err)
	}
	return tmpdir + "/" +header.Name
}


func writeTempFile(dir string, nametemplate string, contents []byte) string{
	f, err := os.CreateTemp(dir, nametemplate)
	if err != nil {
		fmt.Errorf("could not create tempfile in %s: %v", dir, err)
	}
	//defer os.Remove(f.Name()) // clean up
	fmt.Printf("tmpfile=%s\n",f.Name())
	f.Write(contents)
	f.Close()

	return f.Name()

}


func signFile(filename string, publickey string, privatekey string){
	fmt.Println("     running /sign-file","sha256",privatekey, publickey, filepath.Base(filename))
	out, err := exec.Command("/sign-file","sha256",privatekey, publickey, filename).Output()
	//err := cmd.Run()
	if err != nil {
		fmt.Println("signing %s returned: %s\n error: %v\n",filename, out, err)
		fmt.Errorf("unable to sign kmod: %v\n", err)
		panic(0)
	}
}


func addToTarball(tw *tar.Writer, filename string, header *tar.Header)  error {
	finfo, err := os.Stat(filename)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", filename,  err)
		panic("failed to stat!")
	}

	hdr := &tar.Header{
		Name: header.Name,
		Mode: header.Mode,
		Typeflag: header.Typeflag,
		Size: finfo.Size(),
	}


	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}


	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("failed to read file into the tar: %w", err)
	}
	f.Close()

	return nil

}


func copyDockerConfig(fromfile string) (int64,error){
// stupid hack to work around go-containerregistry hardcoding the name of the docker file
	if fromfile == "" {
		return 0,nil
	}
	home := getenv("HOME","/root")

	os.Mkdir(home+"/.docker", 0700)

	source, err := os.Open(fromfile)
        if err != nil {
                return 0, err
        }
        defer source.Close()

        destination, err := os.Create(home+"/.docker/config.json")
        if err != nil {
                return 0, err
        }
        defer destination.Close()
        nBytes, err := io.Copy(destination, source)
        return nBytes, err
}



func main() {

	// get the env vars we are using for setup, or set some sensible defaults

	var unsignedimagename string
	var signedimagename string
	var fileslist string
	var privkeyfile string
	var pubkeyfile string
	var pullsecret string
	flag.StringVar(&unsignedimagename, "unsignedimage", "", "name of the image to sign")
	flag.StringVar(&signedimagename, "signedimage", "", "name of the signed image to produce")
	flag.StringVar(&fileslist, "filestosign", "", "colon seperated list of kmods to sign")
	flag.StringVar(&privkeyfile, "key", "", "path to file containing private key for signing")
	flag.StringVar(&pubkeyfile, "cert", "", "path to file containing public key for signing")
	flag.StringVar(&pullsecret, "pullsecret", "", "path to file containing credentials for pulling/pushing images")

	flag.Parse()

	checkarg(&unsignedimagename, "UNSIGNEDIMAGE", "")
	checkarg(&signedimagename, "SIGNEDIMAGE", unsignedimagename+"signed")
	checkarg(&fileslist, "FILESTOSIGN", "")
	checkarg(&privkeyfile, "KEYSECRET", "")
	checkarg(&pubkeyfile, "CERTSECRET", "")
	checkarg(&pullsecret, "PULLSECRET", "")
	// if we've made it this far the arguements are sane

	// get a temp dir to copy kmods into for signing
	extractiondir, err := os.MkdirTemp("/tmp/", "kmod_signer")
	if err != nil {
		fmt.Errorf("could not create temp dir: %v\n", err)
		panic(err)
	}

	// sets up a tar archive we will use for a new layer
	var b bytes.Buffer
	tarwriter := tar.NewWriter(&b)


	// this is dumb but it seems to be stupidly complex to 
	// set the authconfig to a file from inside the program
	// and the path its looking for is hardcoded *sigh*
	_,err = copyDockerConfig(pullsecret)
	if err != nil{
		fmt.Printf("failed to copy dockerconfig, will try to carry on regardless: %v\n", err)
	}

	//make a map of the files to sign so we can track what we want to sign
	kmodstosign := make(map[string]string)
	for _,x := range strings.Split(fileslist, ":"){
		kmodstosign[x]="not found"
	}

	// set up image download otions
	opts := make([]name.Option, 0)
	ref, err := name.ParseReference(unsignedimagename, opts...)
	if err != nil {
		fmt.Errorf("could not parse the container image name: %v\n", err)
		panic(err)
	}

	descriptor, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		te := &transport.Error{}

		if errors.As(err, &te) && te.StatusCode == http.StatusNotFound {
			fmt.Errorf("could not get image: http.StatusNotFound")
		}

		fmt.Errorf("could not get image: %v", err)
		panic(err)
	}

	img, err := descriptor.Image()
	if err != nil {
		fmt.Errorf("could not Image(): %v", err)
		panic(err)
	}
	fmt.Printf("\n== Successfully pulled image: %s\n" ,unsignedimagename)
	fmt.Printf("\n== Looking for files: %s\n" , strings.Replace(fileslist, ":", " ",-1))

	/*
	** loop through all the layers in the image from the top down
	*/
	layers,_ := img.Layers()
	for i := len(layers)-1; i >=0; i-- {
		fmt.Printf("== Searching layer %d\n" ,i)
		currentlayer := layers[i]
		layerreader, err := currentlayer.Uncompressed()
		if err != nil {
			fmt.Errorf("could not get layer: %v", err)
			panic(err)
		}

		/*
		** loop through all the files in the layer
		*/
		tarreader := tar.NewReader(layerreader)
		for {
			header,_ := tarreader.Next()
			if err == io.EOF || header == nil {
				break // End of archive
			}

			// paths in a layer are relative, and supplied paths are absolute so canonicalise
			canonfilename := canonicalisePath(header.Name)
			if kmodstosign[canonfilename] == "not found" {
				fmt.Printf("\n == Found kmod: %s\n" ,header.Name)
				//its a file we wanted and haven't already seen
				//extract to the local filesystem
				kmodstosign[canonfilename] = extractFile(extractiondir, header, tarreader)
				fmt.Printf("\n  == Signing: %s\n" ,header.Name)

				//sign it
				signFile(kmodstosign[canonfilename], pubkeyfile, privkeyfile)
				fmt.Printf("\n  == Signed successfully: %s\n" ,header.Name)

				// add back in to the new layer
				err := addToTarball( tarwriter, kmodstosign[canonfilename], header)
				if err != nil {
					fmt.Errorf("failed to add %d to layer: %v", canonfilename,  err)
				}
				fmt.Printf("\n  == Added signed file to new layer: %s\n" ,header.Name)

			}

		}
	}
	/*
	for k,v := range kmodstosign {
		fmt.Printf("%s ",k)
		if v == "not found" {
			fmt.Printf("%s\n",v)
		}else{
			fmt.Printf("signed\n",v)
		}
	}
	*/
	//turn our tar archive into a layer
	signedlayer, err := tarball.LayerFromReader(&b, tarball.WithMediaType(types.OCILayer))
	if err != nil {
		fmt.Errorf("failed to generate layer from tar: %v", err)
	}

	// add the layer to the unsigned image
	signedimage, err := mutate.AppendLayers(img, signedlayer)
	if err != nil {
		fmt.Errorf("failed to append layer: %v", err)
	}

	fmt.Printf("\n== Appended new layer to image\n")

	// write the image back to the name:tag set via the envvars
	signedref, err := name.ParseReference(signedimagename, opts...)
	if err != nil {
		fmt.Errorf("failed to parse signed image ref %s: %v", signedimagename, err)
		panic("push image")
	}

	err = remote.Write(signedref, signedimage, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	//err = remote.Write(signedref, signedimage, pushoptions)
	if err != nil {
		fmt.Printf("failed to push signed image: %v\n", err)
		panic(0)
	}
	// we're done successfully, so we need a nice friendly message to say that
	fmt.Printf("\n== Pushed image back to repo: %s\n\n",signedimagename)
	os.Exit(0)
}

