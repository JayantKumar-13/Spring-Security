package com.Security_demo.SpringSecdemo.service;

import com.Security_demo.SpringSecdemo.Exceptions.ResourceNotFoundException;
import com.Security_demo.SpringSecdemo.dto.PostDTO;
import com.Security_demo.SpringSecdemo.entities.PostEntity;
import com.Security_demo.SpringSecdemo.repositories.PostRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class PostServiceImpl implements PostService{

    private final PostRepository postRepository;
    private final ModelMapper modelMapper;

    @Override
    public List<PostDTO> getAllPosts() {
        return postRepository.findAll()
                .stream()
                .map(postEntity -> modelMapper.map(postEntity , PostDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public PostDTO createNewPost(PostDTO inputPost) {
        PostEntity postEntity = modelMapper.map(inputPost , PostEntity.class);
        postRepository.save(postEntity);
        return modelMapper.map(postEntity , PostDTO.class);
    }

    @Override
    public PostDTO getPostById(Long postId) {
        PostEntity postEntity = postRepository.findById(postId).orElseThrow(() -> new ResourceNotFoundException("Post With id " + postId + "Not found"));
        return modelMapper.map(postEntity , PostDTO.class);

    }
}
