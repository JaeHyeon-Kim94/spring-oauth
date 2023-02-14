package io.oauth.authorizationserver.converter;

import org.springframework.core.convert.converter.Converter;

import java.time.LocalDate;

public class StringToLocalDateConverter implements Converter<String, LocalDate> {
    @Override
    public LocalDate convert(String source) {
        String[] split = source.split("-");
        if(split.length != 3) return null;
        int[] arr = new int[3];

        for(int i=0; i<3; i++){
            arr[i] = Integer.parseInt(split[i]);
        }


        LocalDate birth = LocalDate.of(arr[0], arr[1], arr[2]);
        return birth;
    }

}
