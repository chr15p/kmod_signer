package registry

import (
	"archive/tar"
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type registry struct {
}
/*
type Registry interface {
	ImageExists(ctx context.Context, image string, po *kmmv1beta1.PullOptions, registryAuthGetter auth.RegistryAuthGetter) (bool, error)
	VerifyModuleExists(layer v1.Layer, pathPrefix, kernelVersion, moduleFileName string) bool
	GetLayersDigests(ctx context.Context, image string, po *kmmv1beta1.PullOptions, registryAuthGetter auth.RegistryAuthGetter) ([]string, *RepoPullConfig, error)
	GetLayerByDigest(digest string, pullConfig *RepoPullConfig) (v1.Layer, error)
}
*/
func NewRegistry() *registry {
	return &registry{}
}

func (r *registry) GetImageByName(imageName string, auth authn.Authenticator) (v1.Image, error){

	ref, err := r.parseReference(imageName)
	if err != nil {
		return nil, err
	}

	descriptor, err := remote.Get(ref, remote.WithAuth(auth))
	if err != nil {
		return nil,fmt.Errorf("could not get image: %w", err)
	}

	img, err := descriptor.Image()
	if err != nil {
		return nil,fmt.Errorf("could not call image: %w", err)
	}
	return img, nil
}


func (r *registry) parseReference(imageName string) (name.Reference, error){
	opts := make([]name.Option, 0)
	ref, err := name.ParseReference(imageName, opts...)
	if err != nil {
		return nil,fmt.Errorf("could not parse the container image %s: %w", imageName, err)
	}

	return ref, nil
}


func (r *registry) WriteImageByName(imageName string, image v1.Image, auth authn.Authenticator) error{

	ref, err := r.parseReference(imageName)
	if err != nil {
		return err
	}

	err = remote.Write(ref, image, remote.WithAuth(auth))
	if err != nil {
		return fmt.Errorf("failed to push signed image: %w", err)
	}
	return nil
}

func (r *registry) AddLayerToImage(layer io.Reader, image v1.Image, mt types.MediaType) (v1.Image, error) {

	//turn our tar archive into a layer
	signedlayer, err := tarball.LayerFromReader(layer, tarball.WithMediaType(mt))
	if err != nil {
		return nil,fmt.Errorf("failed to generate layer from tar: %w", err)
	}

	// add the layer to the unsigned image
	newImage, err := mutate.AppendLayers(image, signedlayer)
	if err != nil {
		return nil, fmt.Errorf("failed to append layer: %w", err)
	}

	return newImage, nil
}

func (r *registry) GetMediaType(image v1.Image) (types.MediaType, error){
	layers, err := image.Layers()
	if err != nil {
		return types.OCIUncompressedLayer, fmt.Errorf("could not get the layers from image", err)
	}

	return layers[len(layers)-1].MediaType()
}



func (r *registry) ModifyFilesInImage( image v1.Image, fn func(filename string, header *tar.Header, tarreader io.Reader) error) error{

	layers, err := image.Layers()
	if err != nil {
		return fmt.Errorf("could not get the layers from the fetched image", err)
	}
	for i := len(layers) - 1; i >= 0; i-- {
		fmt.Printf("== Searching layer %d\n", i)
		currentlayer := layers[i]


		layerreader, err := currentlayer.Uncompressed()
		if err != nil {
			return fmt.Errorf("could not get layer: %w", err)
		}

		/*
		** loop through all the files in the layer
		 */
		tarreader := tar.NewReader(layerreader)
		for {
			header, err := tarreader.Next()
			if err == io.EOF || header == nil {
				break // End of archive
			}
			err = fn(header.Name, header, tarreader)
			if err != nil {
				return fmt.Errorf("died processing file %s: %w", header.Name, err)
			}
		}
	}

	return err
}
